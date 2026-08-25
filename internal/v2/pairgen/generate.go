// Package pairgen creates one offline pair of burn-on-use N2 artifacts. It
// owns no network capability and never returns secret material to callers.
package pairgen

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/rendezvousadmission"
)

const (
	ManifestProfile        = "winkyou-test-direct-pair-manifest/1"
	ClipboardRoleInitiator = "initiator"
	ClipboardRoleResponder = "responder"

	InitiatorFilename = "initiator.winkyou.json"
	ResponderFilename = "responder.winkyou.json"
	AdmissionFilename = "rendezvous-admission.json"
	ManifestFilename  = "manifest.json"
)

var (
	ErrInvalidOptions       = errors.New("pairgen: invalid options")
	ErrRandomUnavailable    = errors.New("pairgen: random source unavailable")
	ErrOutputUnavailable    = errors.New("pairgen: private output unavailable")
	ErrClipboardUnavailable = errors.New("pairgen: clipboard unavailable")
	ErrInjectedFailure      = errors.New("pairgen: injected failure")
)

type Options struct {
	OutDir                      string
	ClipboardRole               string
	AcknowledgeClipboardHistory bool
}

type Result struct {
	ClipboardUsed bool
}

type manifest struct {
	Manifest             string   `json:"manifest"`
	ArtifactProfile      string   `json:"artifact_profile"`
	DirectAttemptProfile string   `json:"direct_attempt_profile"`
	RendezvousProfile    string   `json:"rendezvous_profile"`
	SecureChannelProfile string   `json:"secure_channel_profile"`
	ArtifactFingerprint  string   `json:"artifact_fingerprint"`
	IssuedAt             string   `json:"issued_at"`
	ExpiresAt            string   `json:"expires_at"`
	Files                []string `json:"files"`
}

type dependencies struct {
	random    io.Reader
	now       func() time.Time
	clipboard func(context.Context, []byte) error
	hook      func(string) error
}

func Generate(ctx context.Context, options Options) (Result, error) {
	return generate(ctx, options, dependencies{
		random: rand.Reader,
		now:    time.Now,
		clipboard: func(ctx context.Context, payload []byte) error {
			return writeClipboard(ctx, payload)
		},
	})
}

func generate(ctx context.Context, options Options, deps dependencies) (result Result, resultErr error) {
	if ctx == nil || deps.random == nil || deps.now == nil || options.OutDir == "" ||
		(options.ClipboardRole != "" && options.ClipboardRole != ClipboardRoleInitiator && options.ClipboardRole != ClipboardRoleResponder) ||
		(options.ClipboardRole == "" && options.AcknowledgeClipboardHistory) ||
		(options.ClipboardRole != "" && !options.AcknowledgeClipboardHistory) {
		return Result{}, ErrInvalidOptions
	}
	if _, err := os.Lstat(options.OutDir); !errors.Is(err, os.ErrNotExist) {
		return Result{}, ErrOutputUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Result{}, ErrOutputUnavailable
	}

	material, psk, err := generateMaterial(deps.random, deps.now())
	if err != nil {
		return Result{}, err
	}
	defer clear(psk[:])
	initiator, responder, fingerprint, err := directattempt.EncodeArtifactPair(material, psk)
	if err != nil {
		return Result{}, ErrRandomUnavailable
	}
	defer clear(initiator)
	defer clear(responder)

	admissionPayload, err := json.Marshal(rendezvousadmission.Admission{
		Profile: directattempt.RendezvousPresenceProfile, AssociationID: material.AssociationID,
		IssuedAt: material.IssuedAt.Format(time.RFC3339), ExpiresAt: material.ExpiresAt.Format(time.RFC3339),
	})
	if err != nil {
		return Result{}, ErrOutputUnavailable
	}
	defer clear(admissionPayload)
	manifestPayload, err := json.Marshal(manifest{
		Manifest: ManifestProfile, ArtifactProfile: directattempt.ArtifactProfile,
		DirectAttemptProfile: directattempt.DirectAttemptProfile,
		RendezvousProfile:    directattempt.RendezvousPresenceProfile,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile,
		ArtifactFingerprint:  fingerprint,
		IssuedAt:             material.IssuedAt.Format(time.RFC3339), ExpiresAt: material.ExpiresAt.Format(time.RFC3339),
		Files: []string{InitiatorFilename, ResponderFilename, AdmissionFilename},
	})
	if err != nil {
		return Result{}, ErrOutputUnavailable
	}
	defer clear(manifestPayload)

	createdDirectory := false
	created := make([]string, 0, 4)
	defer func() {
		if resultErr == nil || !createdDirectory {
			return
		}
		for index := len(created) - 1; index >= 0; index-- {
			_ = os.Remove(created[index])
		}
		_ = os.Remove(options.OutDir)
	}()
	if err := os.Mkdir(options.OutDir, 0o700); err != nil {
		return Result{}, ErrOutputUnavailable
	}
	createdDirectory = true
	if err := protectPrivatePath(options.OutDir, true); err != nil {
		return Result{}, ErrOutputUnavailable
	}

	write := func(name string, payload []byte) error {
		if deps.hook != nil {
			if err := deps.hook("before_" + name); err != nil {
				return err
			}
		}
		path := filepath.Join(options.OutDir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return ErrOutputUnavailable
		}
		created = append(created, path)
		// Lock down and verify the empty file before writing any secret bytes.
		// This closes the Windows creation-to-DACL window while Linux's 0600
		// mode remains the first line of defense.
		if err := protectPrivatePath(path, false); err != nil {
			_ = file.Close()
			return ErrOutputUnavailable
		}
		if _, err := file.Write(payload); err != nil {
			_ = file.Close()
			return ErrOutputUnavailable
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return ErrOutputUnavailable
		}
		if err := file.Close(); err != nil {
			return ErrOutputUnavailable
		}
		if err := protectPrivatePath(path, false); err != nil {
			return ErrOutputUnavailable
		}
		if deps.hook != nil {
			if err := deps.hook("after_" + name); err != nil {
				return err
			}
		}
		return nil
	}

	for _, current := range []struct {
		name    string
		payload []byte
	}{{InitiatorFilename, initiator}, {ResponderFilename, responder}, {AdmissionFilename, admissionPayload}} {
		if err := write(current.name, current.payload); err != nil {
			return Result{}, stableGenerationError(err)
		}
	}
	if err := syncPrivateDirectory(options.OutDir); err != nil {
		return Result{}, ErrOutputUnavailable
	}
	if err := write(ManifestFilename, manifestPayload); err != nil {
		return Result{}, stableGenerationError(err)
	}
	if err := syncPrivateDirectory(options.OutDir); err != nil {
		return Result{}, ErrOutputUnavailable
	}
	if err := validateCompleteOutput(options.OutDir); err != nil {
		return Result{}, ErrOutputUnavailable
	}
	// Clipboard delivery happens only after the manifest commit marker and the
	// complete private output have been synchronized and revalidated. A crash
	// can therefore never expose a recipient artifact through the clipboard
	// while leaving only an uncommitted directory on disk.
	if options.ClipboardRole != "" {
		payload := initiator
		if options.ClipboardRole == ClipboardRoleResponder {
			payload = responder
		}
		if deps.clipboard == nil || deps.clipboard(ctx, payload) != nil {
			return Result{}, ErrClipboardUnavailable
		}
		result.ClipboardUsed = true
	}
	return result, nil
}

func generateMaterial(random io.Reader, now time.Time) (directattempt.ArtifactMaterial, [32]byte, error) {
	issuedAt := now.UTC().Truncate(time.Second)
	if issuedAt.Year() < 1970 || issuedAt.Year() > 9998 {
		return directattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
	}
	var psk [32]byte
	if _, err := io.ReadFull(random, psk[:]); err != nil {
		clear(psk[:])
		return directattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
	}
	identifiers := make([]string, 5)
	seen := make(map[string]struct{}, len(identifiers))
	for index := range identifiers {
		var value [16]byte
		if _, err := io.ReadFull(random, value[:]); err != nil {
			clear(value[:])
			clear(psk[:])
			return directattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
		}
		identifiers[index] = base64.RawURLEncoding.EncodeToString(value[:])
		clear(value[:])
		if _, duplicate := seen[identifiers[index]]; duplicate {
			clear(psk[:])
			return directattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
		}
		seen[identifiers[index]] = struct{}{}
	}
	return directattempt.ArtifactMaterial{
		CredentialID: identifiers[0], AttemptID: identifiers[1],
		InitiatorParticipantID: identifiers[2], ResponderParticipantID: identifiers[3],
		AssociationID: identifiers[4], IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(10 * time.Minute),
	}, psk, nil
}

func validateCompleteOutput(directory string) error {
	if err := validatePrivatePath(directory, true); err != nil {
		return err
	}
	for _, name := range []string{InitiatorFilename, ResponderFilename, AdmissionFilename, ManifestFilename} {
		if err := validatePrivatePath(filepath.Join(directory, name), false); err != nil {
			return err
		}
	}
	return nil
}

func stableGenerationError(err error) error {
	if errors.Is(err, ErrInjectedFailure) {
		return ErrInjectedFailure
	}
	return ErrOutputUnavailable
}
