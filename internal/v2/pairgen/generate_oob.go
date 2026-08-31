package pairgen

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairingcontext"
)

const (
	OOBProfilePredictive = "predictive"
	OOBProfileAsymmetric = "asymmetric"
	OOBProfileHard16K    = "hard-16k"

	OOBMappingSetInitiator = "initiator"
	OOBMappingSetResponder = "responder"

	OOBInitiatorFilename = "initiator.artifact.json"
	OOBResponderFilename = "responder.artifact.json"
	OOBManifestFilename  = "manifest.json"
)

type OOBOptions struct {
	OutDir         string
	Profile        string
	MappingSetRole string
}

type OOBResult struct{}

// GenerateOOB writes exactly two product artifacts and one secret-free
// manifest. It has no clipboard path and returns no identifiers or paths.
func GenerateOOB(ctx context.Context, options OOBOptions) (OOBResult, error) {
	return generateOOB(ctx, options, dependencies{random: rand.Reader, now: time.Now})
}

func generateOOB(ctx context.Context, options OOBOptions, deps dependencies) (result OOBResult, resultErr error) {
	profile, resource, initiatorPlanner, responderPlanner, err := resolveOOBProfile(options.Profile, options.MappingSetRole)
	if err != nil || ctx == nil || deps.random == nil || deps.now == nil || options.OutDir == "" {
		return OOBResult{}, ErrInvalidOptions
	}
	if _, err := os.Lstat(options.OutDir); !errors.Is(err, os.ErrNotExist) {
		return OOBResult{}, ErrOutputUnavailable
	}
	if ctx.Err() != nil {
		return OOBResult{}, ErrOutputUnavailable
	}

	material, psk, err := generateOOBMaterial(deps.random, deps.now(), profile, resource, initiatorPlanner, responderPlanner)
	if err != nil {
		return OOBResult{}, err
	}
	defer clear(psk[:])
	set, err := gatecattempt.EncodeArtifactSet(material, psk)
	if err != nil {
		return OOBResult{}, ErrRandomUnavailable
	}
	defer set.Close()

	createdDirectory := false
	created := make([]string, 0, 3)
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
		return OOBResult{}, ErrOutputUnavailable
	}
	createdDirectory = true
	if err := protectPrivatePath(options.OutDir, true); err != nil {
		return OOBResult{}, ErrOutputUnavailable
	}

	write := func(name string, payload []byte) error {
		if deps.hook != nil {
			if err := deps.hook("before_oob_" + name); err != nil {
				return err
			}
		}
		path := filepath.Join(options.OutDir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return ErrOutputUnavailable
		}
		created = append(created, path)
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
			if err := deps.hook("after_oob_" + name); err != nil {
				return err
			}
		}
		return nil
	}
	for _, current := range []struct {
		name    string
		payload []byte
	}{{OOBInitiatorFilename, set.Initiator}, {OOBResponderFilename, set.Responder}} {
		if err := write(current.name, current.payload); err != nil {
			return OOBResult{}, stableGenerationError(err)
		}
	}
	if err := syncPrivateDirectory(options.OutDir); err != nil {
		return OOBResult{}, ErrOutputUnavailable
	}
	// The manifest is the commit marker and is always created last.
	if err := writeOOBManifestCommit(options.OutDir, set.Manifest, deps, &created); err != nil {
		return OOBResult{}, stableGenerationError(err)
	}
	if err := syncPrivateDirectory(options.OutDir); err != nil {
		return OOBResult{}, ErrOutputUnavailable
	}
	if err := validateCompleteOOBOutput(options.OutDir); err != nil {
		return OOBResult{}, ErrOutputUnavailable
	}
	return OOBResult{}, nil
}

// writeOOBManifestCommit makes the final manifest name visible with one
// no-replace link operation. A crash before the link leaves no commit marker;
// a crash before the temporary link is removed leaves link-count two, which
// every private-file reader rejects fail-closed.
func writeOOBManifestCommit(directory string, payload []byte, deps dependencies, created *[]string) error {
	if deps.hook != nil {
		if err := deps.hook("before_oob_" + OOBManifestFilename); err != nil {
			return err
		}
	}
	temporary := filepath.Join(directory, ".manifest.pending")
	committed := filepath.Join(directory, OOBManifestFilename)
	if err := WritePrivateFileExclusive(temporary, payload); err != nil {
		return ErrOutputUnavailable
	}
	*created = append(*created, temporary)
	if err := SyncPrivateDirectory(directory); err != nil {
		return ErrOutputUnavailable
	}
	if err := os.Link(temporary, committed); err != nil {
		return ErrOutputUnavailable
	}
	*created = append(*created, committed)
	if err := SyncPrivateDirectory(directory); err != nil {
		return ErrOutputUnavailable
	}
	if deps.afterOOBManifestLink != nil {
		if err := deps.afterOOBManifestLink(); err != nil {
			return err
		}
	}
	if err := os.Remove(temporary); err != nil {
		return ErrOutputUnavailable
	}
	if err := SyncPrivateDirectory(directory); err != nil {
		return ErrOutputUnavailable
	}
	if err := validatePrivatePath(committed, false); err != nil {
		return ErrOutputUnavailable
	}
	if deps.hook != nil {
		if err := deps.hook("after_oob_" + OOBManifestFilename); err != nil {
			return err
		}
	}
	return nil
}

func resolveOOBProfile(choice, mappingSetRole string) (hardnatplan.Profile, hardnatplan.ResourceClass, hardnatplan.Role, hardnatplan.Role, error) {
	switch choice {
	case OOBProfilePredictive:
		if mappingSetRole != "" {
			break
		}
		return hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive,
			hardnatplan.RoleInitiator, hardnatplan.RoleResponder, nil
	case OOBProfileAsymmetric:
		switch mappingSetRole {
		case OOBMappingSetInitiator:
			return hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric,
				hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet, nil
		case OOBMappingSetResponder:
			return hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric,
				hardnatplan.RoleTargetSet, hardnatplan.RoleMappingSet, nil
		}
	case OOBProfileHard16K:
		if mappingSetRole != "" {
			break
		}
		return hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab,
			hardnatplan.RoleInitiator, hardnatplan.RoleResponder, nil
	}
	return "", "", "", "", ErrInvalidOptions
}

func generateOOBMaterial(randomSource io.Reader, now time.Time, profile hardnatplan.Profile, resource hardnatplan.ResourceClass, initiatorPlanner, responderPlanner hardnatplan.Role) (gatecattempt.ArtifactMaterial, [32]byte, error) {
	issuedAt := now.UTC().Truncate(time.Second)
	if issuedAt.Year() < 1970 || issuedAt.Year() > 9998 {
		return gatecattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
	}
	var psk [32]byte
	if _, err := io.ReadFull(randomSource, psk[:]); err != nil {
		return gatecattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
	}
	identifiers := make([]string, 5)
	seen := make(map[string]struct{}, len(identifiers))
	for index := range identifiers {
		var value [16]byte
		if _, err := io.ReadFull(randomSource, value[:]); err != nil {
			clear(psk[:])
			return gatecattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
		}
		identifiers[index] = base64.RawURLEncoding.EncodeToString(value[:])
		clear(value[:])
		if _, duplicate := seen[identifiers[index]]; duplicate {
			clear(psk[:])
			return gatecattempt.ArtifactMaterial{}, [32]byte{}, ErrRandomUnavailable
		}
		seen[identifiers[index]] = struct{}{}
	}
	return gatecattempt.ArtifactMaterial{
		CredentialID: identifiers[0], AttemptID: identifiers[1], InitiatorParticipantID: identifiers[2],
		ResponderParticipantID: identifiers[3], OOBChannelID: identifiers[4], PlannerProfile: profile,
		ResourceClass: resource, InitiatorPlannerRole: initiatorPlanner, ResponderPlannerRole: responderPlanner,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(pairingcontext.MaxPairingLifetime),
	}, psk, nil
}

func validateCompleteOOBOutput(directory string) error {
	if err := validatePrivatePath(directory, true); err != nil {
		return err
	}
	for _, name := range []string{OOBInitiatorFilename, OOBResponderFilename, OOBManifestFilename} {
		if err := validatePrivatePath(filepath.Join(directory, name), false); err != nil {
			return err
		}
	}
	return nil
}
