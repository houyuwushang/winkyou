package portforward

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

const alpn = "winkyou-port-forward/1"

var (
	certificateNotBefore = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificateNotAfter  = time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC)
)

func makeTLSConfig(secret []byte, localRole, peerRole string, server bool) (*tls.Config, error) {
	cert, err := makeRoleCertificate(secret, localRole)
	if err != nil {
		return nil, err
	}
	expectedPeer := deriveRolePublicKey(secret, peerRole)
	verifyPeer := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return fmt.Errorf("portforward: expected one peer certificate, got %d", len(rawCerts))
		}
		peer, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("portforward: parse peer certificate: %w", err)
		}
		publicKey, ok := peer.PublicKey.(ed25519.PublicKey)
		if !ok || !bytes.Equal(publicKey, expectedPeer) {
			return fmt.Errorf("portforward: peer authentication failed")
		}
		if peer.Subject.CommonName != roleCommonName(peerRole) {
			return fmt.Errorf("portforward: unexpected peer role %q", peer.Subject.CommonName)
		}
		now := time.Now()
		if now.Before(peer.NotBefore) || now.After(peer.NotAfter) {
			return fmt.Errorf("portforward: peer certificate is outside its validity window")
		}
		if err := peer.CheckSignature(peer.SignatureAlgorithm, peer.RawTBSCertificate, peer.Signature); err != nil {
			return fmt.Errorf("portforward: invalid peer certificate signature: %w", err)
		}
		return nil
	}

	cfg := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpn},
		VerifyPeerCertificate: verifyPeer,
	}
	if server {
		// The certificate is self-signed but pinned to a role-specific public key
		// derived from the shared secret, so no ambient CA roots are involved.
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		// Standard chain validation cannot validate our deterministic self-signed
		// certificate. VerifyPeerCertificate above performs strict public-key pinning.
		cfg.InsecureSkipVerify = true //nolint:gosec
		cfg.ServerName = "winkyou.invalid"
	}
	return cfg, nil
}

func makeRoleCertificate(secret []byte, role string) (tls.Certificate, error) {
	privateKey := deriveRolePrivateKey(secret, role)
	serialDigest := hmacDigest(secret, "winkyou-port-forward/cert-serial/"+role)
	serial := new(big.Int).SetBytes(serialDigest[:16])
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: roleCommonName(role),
		},
		NotBefore:             certificateNotBefore,
		NotAfter:              certificateNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("portforward: create %s certificate: %w", role, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}, nil
}

func deriveRolePublicKey(secret []byte, role string) ed25519.PublicKey {
	privateKey := deriveRolePrivateKey(secret, role)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

func deriveRolePrivateKey(secret []byte, role string) ed25519.PrivateKey {
	digest := hmacDigest(secret, "winkyou-port-forward/tls-key/"+role)
	return ed25519.NewKeyFromSeed(digest[:])
}

func hmacDigest(secret []byte, label string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(label))
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func roleCommonName(role string) string {
	return "winkyou-" + role
}

func deriveQUICKey(secret []byte, label string) [32]byte {
	digest := hmacDigest(secret, "winkyou-port-forward/quic/"+label)
	var out [32]byte
	copy(out[:], digest[:])
	return out
}
