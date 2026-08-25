package rendezvouscarrier

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strings"
)

type TLSVerification string

const (
	TLSSystemRoots TLSVerification = "system_roots"
	TLSSPKISHA256  TLSVerification = "spki_sha256"
)

type TLSConfig struct {
	Verification TLSVerification
	ServerName   string
	SPKISHA256   string
}

// ValidateTLSConfig performs the exact TLS schema check without resolving a
// name, opening a connection, or retaining decoded pin material. Product
// entry points use it before acquiring an attempt lease.
func ValidateTLSConfig(config TLSConfig) error {
	pin, err := config.validate()
	clear(pin[:])
	return err
}

func (config TLSConfig) validate() ([sha256.Size]byte, error) {
	var pin [sha256.Size]byte
	switch config.Verification {
	case TLSSystemRoots:
		if strings.TrimSpace(config.ServerName) == "" || config.ServerName != strings.TrimSpace(config.ServerName) || config.SPKISHA256 != "" {
			return pin, ErrTLSConfig
		}
	case TLSSPKISHA256:
		if config.ServerName != "" || config.SPKISHA256 == "" {
			return pin, ErrTLSConfig
		}
		decoded, err := base64.RawURLEncoding.DecodeString(config.SPKISHA256)
		if err != nil || len(decoded) != len(pin) || base64.RawURLEncoding.EncodeToString(decoded) != config.SPKISHA256 {
			clear(decoded)
			return pin, ErrTLSConfig
		}
		copy(pin[:], decoded)
		clear(decoded)
	default:
		return pin, ErrTLSConfig
	}
	return pin, nil
}

func secureRendezvous(ctx context.Context, connection net.Conn, config TLSConfig) (net.Conn, error) {
	pin, err := config.validate()
	if err != nil {
		return nil, err
	}
	defer clear(pin[:])
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if config.Verification == TLSSystemRoots {
		tlsConfig.ServerName = config.ServerName
	} else {
		tlsConfig.InsecureSkipVerify = true // exact SPKI pin below is authoritative
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrTLSHandshake
			}
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			matched := digest == pin
			clear(digest[:])
			if !matched {
				return ErrTLSHandshake
			}
			return nil
		}
	}
	secured := tls.Client(connection, tlsConfig)
	if err := secured.HandshakeContext(ctx); err != nil {
		_ = secured.Close()
		return nil, ErrTLSHandshake
	}
	if secured.ConnectionState().Version != tls.VersionTLS13 {
		_ = secured.Close()
		return nil, ErrTLSHandshake
	}
	return secured, nil
}
