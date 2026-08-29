package hardnatattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairingcontext"
)

const (
	ArtifactProfile       = "winkyou-test-hard-nat-attempt/1"
	DirectAttemptProfile  = "winkyou-test-hard-nat-control/1"
	OOBCarrierProfile     = "caller-provided-bounded-stream/1"
	ObservationProfile    = "rfc5780-allocation-tomography/1"
	ManifestProfile       = "winkyou-test-hard-nat-manifest/1"
	NoiseBindingLabel     = "winkyou test-only hard NAT binding v1\n"
	MaxArtifactBytes      = 4096
	MaxManifestBytes      = 4096
	ObservationGeneration = "1"
)

var (
	ErrInvalidArtifact       = errors.New("hardnatattempt: invalid artifact")
	ErrUnsupportedProfile    = errors.New("hardnatattempt: unsupported profile")
	ErrCredentialNotYetValid = errors.New("hardnatattempt: credential not yet valid")
	ErrCredentialExpired     = errors.New("hardnatattempt: credential expired")
	ErrSecretUnavailable     = errors.New("hardnatattempt: pairing secret unavailable")
	ErrInvalidManifest       = errors.New("hardnatattempt: invalid manifest")
)

type Role = directattempt.Role

const (
	RoleInitiator = directattempt.RoleInitiator
	RoleResponder = directattempt.RoleResponder
)

type pairingSecret struct {
	value [32]byte
	set   bool
}

func (secret *pairingSecret) UnmarshalJSON(payload []byte) error {
	if secret == nil {
		return ErrInvalidArtifact
	}
	secret.zeroize()
	if len(payload) != 45 || payload[0] != '"' || payload[len(payload)-1] != '"' ||
		bytes.IndexByte(payload[1:len(payload)-1], '\\') >= 0 {
		return ErrInvalidArtifact
	}
	n, err := base64.RawURLEncoding.Decode(secret.value[:], payload[1:len(payload)-1])
	if err != nil || n != len(secret.value) {
		secret.zeroize()
		return ErrInvalidArtifact
	}
	var canonical [43]byte
	base64.RawURLEncoding.Encode(canonical[:], secret.value[:])
	valid := bytes.Equal(canonical[:], payload[1:len(payload)-1])
	clear(canonical[:])
	if !valid {
		secret.zeroize()
		return ErrInvalidArtifact
	}
	secret.set = true
	return nil
}

func (pairingSecret) MarshalJSON() ([]byte, error) { return nil, ErrSecretUnavailable }

func (secret *pairingSecret) zeroize() {
	if secret != nil {
		clear(secret.value[:])
		secret.set = false
	}
}

type wireArtifact struct {
	Artifact               string        `json:"artifact"`
	DirectAttemptProfile   string        `json:"direct_attempt_profile"`
	PlannerProfile         string        `json:"planner_profile"`
	ResourceClass          string        `json:"resource_class"`
	OOBCarrierProfile      string        `json:"oob_carrier_profile"`
	ObservationProfile     string        `json:"observation_profile"`
	OOBChannelID           string        `json:"oob_channel_id"`
	LocalRole              string        `json:"local_role"`
	InitiatorPlannerRole   string        `json:"initiator_planner_role"`
	ResponderPlannerRole   string        `json:"responder_planner_role"`
	Protocol               string        `json:"protocol"`
	AuthScope              string        `json:"auth_scope"`
	CredentialID           string        `json:"credential_id"`
	PairingSecret          pairingSecret `json:"pairing_secret"`
	AttemptID              string        `json:"attempt_id"`
	ObservationGeneration  string        `json:"observation_generation"`
	InitiatorParticipantID string        `json:"initiator_participant_id"`
	ResponderParticipantID string        `json:"responder_participant_id"`
	InitiatorGovernorScope string        `json:"initiator_governor_scope"`
	ResponderGovernorScope string        `json:"responder_governor_scope"`
	SecureChannelProfile   string        `json:"secure_channel_profile"`
	InitiatorChannelRole   string        `json:"initiator_channel_role"`
	ResponderChannelRole   string        `json:"responder_channel_role"`
	EarlyData              string        `json:"early_data"`
	Resumption             string        `json:"resumption"`
	RuntimeFallback        string        `json:"runtime_fallback"`
	IssuedAt               string        `json:"issued_at"`
	ExpiresAt              string        `json:"expires_at"`
	ArtifactFingerprint    string        `json:"artifact_fingerprint"`
}

// Artifact contains no endpoint, address, command, hostname, username, path,
// TLS setting, candidate list or resource-count field.
type Artifact struct {
	LocalRole            Role
	PlannerProfile       hardnatplan.Profile
	ResourceClass        hardnatplan.ResourceClass
	InitiatorPlannerRole hardnatplan.Role
	ResponderPlannerRole hardnatplan.Role
	LocalPlannerRole     hardnatplan.Role
	PeerPlannerRole      hardnatplan.Role
	OOBChannelID         string
	CredentialID         string
	AttemptID            string
	IssuedAt             time.Time
	ExpiresAt            time.Time
	Fingerprint          string

	context       pairingcontext.PairingContext
	contextDigest [sha256.Size]byte
	secret        [32]byte
	hasSecret     bool
}

func ParseArtifact(payload []byte, now time.Time) (*Artifact, error) {
	if len(payload) == 0 || len(payload) > MaxArtifactBytes || !json.Valid(payload) || rejectDuplicateMembers(payload) != nil {
		return nil, ErrInvalidArtifact
	}
	var wire wireArtifact
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || requireJSONEOF(decoder) != nil {
		wire.PairingSecret.zeroize()
		return nil, ErrInvalidArtifact
	}
	artifact, err := validateWire(&wire, now.UTC())
	wire.PairingSecret.zeroize()
	return artifact, err
}

func validateWire(wire *wireArtifact, now time.Time) (*Artifact, error) {
	if wire == nil || !wire.PairingSecret.set {
		return nil, ErrInvalidArtifact
	}
	profile := hardnatplan.Profile(wire.PlannerProfile)
	resource := hardnatplan.ResourceClass(wire.ResourceClass)
	if wire.Artifact != ArtifactProfile || wire.DirectAttemptProfile != DirectAttemptProfile ||
		wire.OOBCarrierProfile != OOBCarrierProfile || wire.ObservationProfile != ObservationProfile ||
		wire.Protocol != pairingcontext.ProtocolVersion || wire.SecureChannelProfile != pairingcontext.SelectedSecureChannelProfile {
		return nil, ErrUnsupportedProfile
	}
	if _, err := hardnatbudget.For(profile, resource); err != nil {
		return nil, ErrUnsupportedProfile
	}
	localRole := Role(wire.LocalRole)
	initiatorPlanner := hardnatplan.Role(wire.InitiatorPlannerRole)
	responderPlanner := hardnatplan.Role(wire.ResponderPlannerRole)
	if !localRole.Valid() || !validPlannerRoles(profile, initiatorPlanner, responderPlanner) ||
		wire.AuthScope != pairingcontext.AuthScope || wire.ObservationGeneration != ObservationGeneration ||
		wire.InitiatorGovernorScope != pairingcontext.GovernorScopeMachine || wire.ResponderGovernorScope != pairingcontext.GovernorScopeMachine ||
		wire.InitiatorChannelRole != pairingcontext.ChannelRoleInitiator || wire.ResponderChannelRole != pairingcontext.ChannelRoleResponder ||
		wire.EarlyData != pairingcontext.FeatureDisabled || wire.Resumption != pairingcontext.FeatureDisabled ||
		wire.RuntimeFallback != pairingcontext.FeatureDisabled {
		return nil, ErrInvalidArtifact
	}
	identifiers := []string{wire.CredentialID, wire.AttemptID, wire.InitiatorParticipantID, wire.ResponderParticipantID, wire.OOBChannelID}
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if !validBase64URL(identifier, 16) {
			return nil, ErrInvalidArtifact
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, ErrInvalidArtifact
		}
		seen[identifier] = struct{}{}
	}
	if !validBase64URL(wire.ArtifactFingerprint, sha256.Size) {
		return nil, ErrInvalidArtifact
	}
	fingerprint, err := artifactFingerprint(wire)
	if err != nil || fingerprint != wire.ArtifactFingerprint {
		return nil, ErrInvalidArtifact
	}
	issuedAt, err := pairingcontext.ParseCanonicalUTCSecond(wire.IssuedAt)
	if err != nil {
		return nil, ErrInvalidArtifact
	}
	expiresAt, err := pairingcontext.ParseCanonicalUTCSecond(wire.ExpiresAt)
	if err != nil || expiresAt.Sub(issuedAt) != pairingcontext.MaxPairingLifetime {
		return nil, ErrInvalidArtifact
	}
	if now.Before(issuedAt) {
		return nil, errors.Join(ErrInvalidArtifact, ErrCredentialNotYetValid)
	}
	if !now.Before(expiresAt) {
		return nil, errors.Join(ErrInvalidArtifact, ErrCredentialExpired)
	}
	contextValue := pairingcontext.PairingContext{
		Artifact: pairingcontext.PairingArtifactAcceptance, Protocol: wire.Protocol, AuthScope: wire.AuthScope,
		CredentialID: wire.CredentialID, AttemptID: wire.AttemptID, ObservationGeneration: wire.ObservationGeneration,
		InitiatorParticipantID: wire.InitiatorParticipantID, ResponderParticipantID: wire.ResponderParticipantID,
		InitiatorGovernorScope: wire.InitiatorGovernorScope, ResponderGovernorScope: wire.ResponderGovernorScope,
		SecureChannelProfile: wire.SecureChannelProfile, InitiatorChannelRole: wire.InitiatorChannelRole,
		ResponderChannelRole: wire.ResponderChannelRole, EarlyData: wire.EarlyData, Resumption: wire.Resumption,
		RuntimeFallback: wire.RuntimeFallback, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt,
		OfferFingerprint: wire.ArtifactFingerprint,
	}
	canonical, err := pairingcontext.CanonicalizePairingContext(contextValue)
	if err != nil {
		return nil, ErrInvalidArtifact
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	localPlanner, peerPlanner := initiatorPlanner, responderPlanner
	if localRole == RoleResponder {
		localPlanner, peerPlanner = responderPlanner, initiatorPlanner
	}
	artifact := &Artifact{
		LocalRole: localRole, PlannerProfile: profile, ResourceClass: resource,
		InitiatorPlannerRole: initiatorPlanner, ResponderPlannerRole: responderPlanner,
		LocalPlannerRole: localPlanner, PeerPlannerRole: peerPlanner,
		OOBChannelID: wire.OOBChannelID, CredentialID: wire.CredentialID, AttemptID: wire.AttemptID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, Fingerprint: wire.ArtifactFingerprint,
		context: contextValue, contextDigest: digest, secret: wire.PairingSecret.value, hasSecret: true,
	}
	clear(digest[:])
	return artifact, nil
}

func validPlannerRoles(profile hardnatplan.Profile, initiator, responder hardnatplan.Role) bool {
	switch profile {
	case hardnatplan.ProfilePredictiveEdm:
		return initiator == hardnatplan.RoleInitiator && responder == hardnatplan.RoleResponder
	case hardnatplan.ProfileAsymmetricBirthday:
		return initiator != responder &&
			(initiator == hardnatplan.RoleMappingSet || initiator == hardnatplan.RoleTargetSet) &&
			(responder == hardnatplan.RoleMappingSet || responder == hardnatplan.RoleTargetSet)
	case hardnatplan.ProfileHardBirthday:
		return initiator == hardnatplan.RoleInitiator && responder == hardnatplan.RoleResponder
	default:
		return false
	}
}

func (artifact *Artifact) PairingContext() (pairingcontext.PairingContext, error) {
	if artifact == nil {
		return pairingcontext.PairingContext{}, ErrInvalidArtifact
	}
	return artifact.context, nil
}

func (artifact *Artifact) ContextDigest() ([sha256.Size]byte, error) {
	if artifact == nil {
		return [sha256.Size]byte{}, ErrInvalidArtifact
	}
	return artifact.contextDigest, nil
}

func (artifact *Artifact) TakePSK() ([32]byte, error) {
	if artifact == nil || !artifact.hasSecret {
		return [32]byte{}, ErrSecretUnavailable
	}
	secret := artifact.secret
	clear(artifact.secret[:])
	artifact.hasSecret = false
	return secret, nil
}

func (artifact *Artifact) NoisePrologue() ([]byte, error) {
	if artifact == nil || !validBase64URL(artifact.OOBChannelID, 16) {
		return nil, ErrInvalidArtifact
	}
	envelope, err := hardnatbudget.For(artifact.PlannerProfile, artifact.ResourceClass)
	if err != nil {
		return nil, ErrUnsupportedProfile
	}
	envelopeDigest, err := hardnatbudget.Digest(envelope)
	if err != nil {
		return nil, err
	}
	base, err := pairingcontext.BuildNoisePrologue(artifact.context)
	if err != nil {
		return nil, err
	}
	binding := NoiseBindingLabel +
		"artifact=" + ArtifactProfile + "\n" +
		"carrier=" + OOBCarrierProfile + "\n" +
		"control=" + DirectAttemptProfile + "\n" +
		"observation=" + ObservationProfile + "\n" +
		"planner_profile=" + string(artifact.PlannerProfile) + "\n" +
		"resource_class=" + string(artifact.ResourceClass) + "\n" +
		"initiator_planner_role=" + string(artifact.InitiatorPlannerRole) + "\n" +
		"responder_planner_role=" + string(artifact.ResponderPlannerRole) + "\n" +
		"execution_envelope=" + base64.RawURLEncoding.EncodeToString(envelopeDigest[:]) + "\n" +
		"runtime_fallback=" + pairingcontext.FeatureDisabled + "\n" +
		"oob_channel_id=" + artifact.OOBChannelID + "\n"
	result := make([]byte, 0, len(base)+1+len(binding))
	result = append(result, base...)
	result = append(result, '\n')
	result = append(result, binding...)
	clear(base)
	return result, nil
}

func (artifact *Artifact) Close() {
	if artifact == nil {
		return
	}
	clear(artifact.secret[:])
	clear(artifact.contextDigest[:])
	artifact.hasSecret = false
	artifact.context = pairingcontext.PairingContext{}
}

type ArtifactMaterial struct {
	CredentialID, AttemptID, InitiatorParticipantID, ResponderParticipantID, OOBChannelID string
	PlannerProfile                                                                        hardnatplan.Profile
	ResourceClass                                                                         hardnatplan.ResourceClass
	InitiatorPlannerRole                                                                  hardnatplan.Role
	ResponderPlannerRole                                                                  hardnatplan.Role
	IssuedAt, ExpiresAt                                                                   time.Time
}

type ArtifactSet struct{ Initiator, Responder, Manifest []byte }

func (set *ArtifactSet) Close() {
	if set != nil {
		clear(set.Initiator)
		clear(set.Responder)
		clear(set.Manifest)
		set.Initiator, set.Responder, set.Manifest = nil, nil, nil
	}
}

type generatedSecret [32]byte

func (secret generatedSecret) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(secret[:])
	return []byte("\"" + encoded + "\""), nil
}

type generatedWire struct {
	Artifact               string          `json:"artifact"`
	DirectAttemptProfile   string          `json:"direct_attempt_profile"`
	PlannerProfile         string          `json:"planner_profile"`
	ResourceClass          string          `json:"resource_class"`
	OOBCarrierProfile      string          `json:"oob_carrier_profile"`
	ObservationProfile     string          `json:"observation_profile"`
	OOBChannelID           string          `json:"oob_channel_id"`
	LocalRole              string          `json:"local_role"`
	InitiatorPlannerRole   string          `json:"initiator_planner_role"`
	ResponderPlannerRole   string          `json:"responder_planner_role"`
	Protocol               string          `json:"protocol"`
	AuthScope              string          `json:"auth_scope"`
	CredentialID           string          `json:"credential_id"`
	PairingSecret          generatedSecret `json:"pairing_secret"`
	AttemptID              string          `json:"attempt_id"`
	ObservationGeneration  string          `json:"observation_generation"`
	InitiatorParticipantID string          `json:"initiator_participant_id"`
	ResponderParticipantID string          `json:"responder_participant_id"`
	InitiatorGovernorScope string          `json:"initiator_governor_scope"`
	ResponderGovernorScope string          `json:"responder_governor_scope"`
	SecureChannelProfile   string          `json:"secure_channel_profile"`
	InitiatorChannelRole   string          `json:"initiator_channel_role"`
	ResponderChannelRole   string          `json:"responder_channel_role"`
	EarlyData              string          `json:"early_data"`
	Resumption             string          `json:"resumption"`
	RuntimeFallback        string          `json:"runtime_fallback"`
	IssuedAt               string          `json:"issued_at"`
	ExpiresAt              string          `json:"expires_at"`
	ArtifactFingerprint    string          `json:"artifact_fingerprint"`
}

type Manifest struct {
	Schema               string `json:"schema"`
	ArtifactProfile      string `json:"artifact_profile"`
	DirectAttemptProfile string `json:"direct_attempt_profile"`
	PlannerProfile       string `json:"planner_profile"`
	ResourceClass        string `json:"resource_class"`
	OOBCarrierProfile    string `json:"oob_carrier_profile"`
	ObservationProfile   string `json:"observation_profile"`
	SecureChannelProfile string `json:"secure_channel_profile"`
	RuntimeFallback      string `json:"runtime_fallback"`
	CredentialID         string `json:"credential_id"`
	AttemptID            string `json:"attempt_id"`
	OOBChannelID         string `json:"oob_channel_id"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	ArtifactFingerprint  string `json:"artifact_fingerprint"`
}

func EncodeArtifactSet(material ArtifactMaterial, psk [32]byte) (set ArtifactSet, err error) {
	issued, expires := material.IssuedAt.UTC(), material.ExpiresAt.UTC()
	if issued.Nanosecond() != 0 || expires.Nanosecond() != 0 || expires.Sub(issued) != pairingcontext.MaxPairingLifetime ||
		!validPlannerRoles(material.PlannerProfile, material.InitiatorPlannerRole, material.ResponderPlannerRole) {
		return ArtifactSet{}, ErrInvalidArtifact
	}
	if _, err := hardnatbudget.For(material.PlannerProfile, material.ResourceClass); err != nil {
		return ArtifactSet{}, ErrUnsupportedProfile
	}
	ids := []string{material.CredentialID, material.AttemptID, material.InitiatorParticipantID, material.ResponderParticipantID, material.OOBChannelID}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if !validBase64URL(id, 16) {
			return ArtifactSet{}, ErrInvalidArtifact
		}
		if _, ok := seen[id]; ok {
			return ArtifactSet{}, ErrInvalidArtifact
		}
		seen[id] = struct{}{}
	}
	base := wireArtifact{
		Artifact: ArtifactProfile, DirectAttemptProfile: DirectAttemptProfile,
		PlannerProfile: string(material.PlannerProfile), ResourceClass: string(material.ResourceClass),
		OOBCarrierProfile: OOBCarrierProfile, ObservationProfile: ObservationProfile, OOBChannelID: material.OOBChannelID,
		InitiatorPlannerRole: string(material.InitiatorPlannerRole), ResponderPlannerRole: string(material.ResponderPlannerRole),
		Protocol: pairingcontext.ProtocolVersion, AuthScope: pairingcontext.AuthScope, CredentialID: material.CredentialID,
		AttemptID: material.AttemptID, ObservationGeneration: ObservationGeneration,
		InitiatorParticipantID: material.InitiatorParticipantID, ResponderParticipantID: material.ResponderParticipantID,
		InitiatorGovernorScope: pairingcontext.GovernorScopeMachine, ResponderGovernorScope: pairingcontext.GovernorScopeMachine,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile,
		InitiatorChannelRole: pairingcontext.ChannelRoleInitiator, ResponderChannelRole: pairingcontext.ChannelRoleResponder,
		EarlyData: pairingcontext.FeatureDisabled, Resumption: pairingcontext.FeatureDisabled, RuntimeFallback: pairingcontext.FeatureDisabled,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
	}
	fingerprint, err := artifactFingerprint(&base)
	if err != nil {
		return ArtifactSet{}, err
	}
	encode := func(role Role) ([]byte, error) {
		wire := generatedWire{
			Artifact: base.Artifact, DirectAttemptProfile: base.DirectAttemptProfile, PlannerProfile: base.PlannerProfile,
			ResourceClass: base.ResourceClass, OOBCarrierProfile: base.OOBCarrierProfile, ObservationProfile: base.ObservationProfile,
			OOBChannelID: base.OOBChannelID, LocalRole: string(role), InitiatorPlannerRole: base.InitiatorPlannerRole,
			ResponderPlannerRole: base.ResponderPlannerRole, Protocol: base.Protocol, AuthScope: base.AuthScope,
			CredentialID: base.CredentialID, PairingSecret: generatedSecret(psk), AttemptID: base.AttemptID,
			ObservationGeneration: base.ObservationGeneration, InitiatorParticipantID: base.InitiatorParticipantID,
			ResponderParticipantID: base.ResponderParticipantID, InitiatorGovernorScope: base.InitiatorGovernorScope,
			ResponderGovernorScope: base.ResponderGovernorScope, SecureChannelProfile: base.SecureChannelProfile,
			InitiatorChannelRole: base.InitiatorChannelRole, ResponderChannelRole: base.ResponderChannelRole,
			EarlyData: base.EarlyData, Resumption: base.Resumption, RuntimeFallback: base.RuntimeFallback,
			IssuedAt: base.IssuedAt, ExpiresAt: base.ExpiresAt, ArtifactFingerprint: fingerprint,
		}
		payload, err := json.Marshal(wire)
		if err != nil {
			return nil, ErrInvalidArtifact
		}
		parsed, parseErr := ParseArtifact(payload, issued)
		if parseErr != nil {
			clear(payload)
			return nil, parseErr
		}
		parsed.Close()
		return payload, nil
	}
	set.Initiator, err = encode(RoleInitiator)
	if err != nil {
		return ArtifactSet{}, err
	}
	set.Responder, err = encode(RoleResponder)
	if err != nil {
		clear(set.Initiator)
		return ArtifactSet{}, err
	}
	manifest := Manifest{
		Schema: ManifestProfile, ArtifactProfile: ArtifactProfile, DirectAttemptProfile: DirectAttemptProfile,
		PlannerProfile: string(material.PlannerProfile), ResourceClass: string(material.ResourceClass),
		OOBCarrierProfile: OOBCarrierProfile, ObservationProfile: ObservationProfile,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile, RuntimeFallback: pairingcontext.FeatureDisabled,
		CredentialID: material.CredentialID, AttemptID: material.AttemptID, OOBChannelID: material.OOBChannelID,
		IssuedAt: base.IssuedAt, ExpiresAt: base.ExpiresAt, ArtifactFingerprint: fingerprint,
	}
	set.Manifest, err = json.Marshal(manifest)
	if err != nil {
		set.Close()
		return ArtifactSet{}, ErrInvalidManifest
	}
	if _, err := ParseManifest(set.Manifest); err != nil {
		set.Close()
		return ArtifactSet{}, err
	}
	return set, nil
}

func ParseManifest(payload []byte) (Manifest, error) {
	if len(payload) == 0 || len(payload) > MaxManifestBytes || !json.Valid(payload) || rejectDuplicateMembers(payload) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || requireJSONEOF(decoder) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	profile, resource := hardnatplan.Profile(manifest.PlannerProfile), hardnatplan.ResourceClass(manifest.ResourceClass)
	if manifest.Schema != ManifestProfile || manifest.ArtifactProfile != ArtifactProfile || manifest.DirectAttemptProfile != DirectAttemptProfile ||
		manifest.OOBCarrierProfile != OOBCarrierProfile || manifest.ObservationProfile != ObservationProfile ||
		manifest.SecureChannelProfile != pairingcontext.SelectedSecureChannelProfile || manifest.RuntimeFallback != pairingcontext.FeatureDisabled ||
		!validBase64URL(manifest.CredentialID, 16) || !validBase64URL(manifest.AttemptID, 16) ||
		!validBase64URL(manifest.OOBChannelID, 16) || !validBase64URL(manifest.ArtifactFingerprint, 32) {
		return Manifest{}, ErrInvalidManifest
	}
	if _, err := hardnatbudget.For(profile, resource); err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	issued, e1 := pairingcontext.ParseCanonicalUTCSecond(manifest.IssuedAt)
	expires, e2 := pairingcontext.ParseCanonicalUTCSecond(manifest.ExpiresAt)
	if e1 != nil || e2 != nil || expires.Sub(issued) != pairingcontext.MaxPairingLifetime {
		return Manifest{}, ErrInvalidManifest
	}
	return manifest, nil
}

func artifactFingerprint(wire *wireArtifact) (string, error) {
	if wire == nil {
		return "", ErrInvalidArtifact
	}
	object := map[string]any{
		"artifact": wire.Artifact, "direct_attempt_profile": wire.DirectAttemptProfile,
		"planner_profile": wire.PlannerProfile, "resource_class": wire.ResourceClass,
		"oob_carrier_profile": wire.OOBCarrierProfile, "observation_profile": wire.ObservationProfile,
		"oob_channel_id": wire.OOBChannelID, "initiator_planner_role": wire.InitiatorPlannerRole,
		"responder_planner_role": wire.ResponderPlannerRole, "protocol": wire.Protocol, "auth_scope": wire.AuthScope,
		"credential_id": wire.CredentialID, "attempt_id": wire.AttemptID, "observation_generation": wire.ObservationGeneration,
		"initiator_participant_id": wire.InitiatorParticipantID, "responder_participant_id": wire.ResponderParticipantID,
		"initiator_governor_scope": wire.InitiatorGovernorScope, "responder_governor_scope": wire.ResponderGovernorScope,
		"secure_channel_profile": wire.SecureChannelProfile, "initiator_channel_role": wire.InitiatorChannelRole,
		"responder_channel_role": wire.ResponderChannelRole, "early_data": wire.EarlyData, "resumption": wire.Resumption,
		"runtime_fallback": wire.RuntimeFallback, "issued_at": wire.IssuedAt, "expires_at": wire.ExpiresAt,
	}
	canonical, err := pairingcontext.CanonicalizeFlatStringObject(object)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	result := base64.RawURLEncoding.EncodeToString(digest[:])
	clear(digest[:])
	return result, nil
}

func validBase64URL(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	valid := err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}

func rejectDuplicateMembers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := scanJSONValue(decoder, first); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return ErrInvalidArtifact
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate member %q", name)
			}
			seen[name] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidArtifact
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidArtifact
		}
	default:
		return ErrInvalidArtifact
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidArtifact
		}
		return err
	}
	return nil
}
