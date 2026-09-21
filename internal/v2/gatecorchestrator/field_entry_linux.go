//go:build linux && fieldc1c

package gatecorchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

// RunFieldInitiator is the only issuer path from the explicit field command.
// It never changes defaultDependencies or the ordinary C1b entry behavior.
func RunFieldInitiator(ctx context.Context, path string) (FieldSummary, error) {
	instance, err := fieldc1c.Load(path, "initiator")
	if err != nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	device, err := instance.Device()
	if err != nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	request, err := gatecrequest.LoadPrivate(device.RequestReference)
	if err != nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	artifact, err := loadArtifact(request.ArtifactFile, time.Now())
	if err != nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	defer artifact.Close()
	return runFieldPrepared(ctx, instance, request, artifact, nil, nil)
}

// The fixed child receives no new argv/env or remote path. Its locally
// claimed slot is the sole input to the canonical instance lookup.
func RunFieldResponder(ctx context.Context, input io.Reader, output io.Writer) (FieldSummary, error) {
	if ctx == nil || input == nil || output == nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	claimed, err := gatecstage.ClaimPending(time.Now().UTC())
	if err != nil || claimed == nil || claimed.Artifact == nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	defer claimed.Close()
	path, err := fieldc1c.InstancePath(claimed.Artifact.AttemptID)
	if err != nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	instance, err := fieldc1c.Load(path, "responder")
	if err != nil {
		return invalidFieldSummary(), fieldc1c.ErrInvalid
	}
	return runFieldPrepared(ctx, instance, claimed.Request, claimed.Artifact, input, output)
}

func runFieldPrepared(ctx context.Context, instance fieldc1c.Instance, request gatecrequest.Request, artifact *gatecattempt.Artifact,
	childInput io.Reader, childOutput io.Writer) (summary FieldSummary, runErr error) {
	summary = invalidFieldSummary()
	if ctx == nil || ctx.Err() != nil {
		return summary, fieldc1c.ErrInvalid
	}
	device, err := instance.Device()
	if err != nil {
		return summary, fieldc1c.ErrInvalid
	}
	binding, err := instance.Binding()
	if err != nil {
		return summary, fieldc1c.ErrInvalid
	}
	configuration, err := loadFieldConfiguration(instance, device.ConfigurationReference)
	if err != nil {
		return summary, fieldc1c.ErrInvalid
	}
	if validateFieldMaterial(instance, binding, request, artifact) != nil {
		return summary, fieldc1c.ErrInvalid
	}
	input := preparedInput{request: request, artifact: artifact, configuration: configuration, configPath: device.ConfigurationReference,
		buildVersion: fieldc1c.BuildSHA, childInput: childInput, childOutput: childOutput, progress: func(Progress) error { return nil }}
	if request.Role == gatecattempt.RoleInitiator {
		input.sshAuthority, err = sshassembly.NewFieldAuthority(instance)
		if err != nil {
			return summary, fieldc1c.ErrInvalid
		}
	}
	peer, err := resolveTrustedPeer(input)
	wantLiveness, livenessErr := freezeLivenessBudget(binding.SessionCeiling, binding.MissedRounds)
	if err != nil || livenessErr != nil || peer.liveness == nil || peer.sessionCeiling != binding.SessionCeiling || *peer.liveness != wantLiveness {
		return summary, fieldc1c.ErrInvalid
	}
	authority, err := netif.NewFieldInterfaceAuthority(instance, peer.interfaceName, peer.mtu, peer.localVirtual, peer.remoteVirtual, peer.allowedIPs)
	if err != nil || netif.PreflightFieldInterface(authority) != nil {
		return summary, fieldc1c.ErrInvalid
	}
	state, err := fieldConflictInspector(ctx, input, peer)
	if err != nil || conflictPresent(state) || passiveMachinePreflight() != nil {
		return summary, fieldc1c.ErrInvalid
	}
	factory, err := probeio.NewFieldUDPFactory(instance)
	if err != nil {
		return summary, fieldc1c.ErrInvalid
	}
	evidence, err := instance.ClaimEvidence()
	if err != nil {
		return summary, fieldc1c.ErrInvalid
	}
	started := time.Now()
	var ownedInterface *netif.FieldInterface
	var result Result
	defer func() {
		summary.DurationNS = time.Since(started).Nanoseconds()
		summary.Profile = binding.Profile
		summary.Class, summary.Stage = "success", StageTerminal
		if runErr != nil {
			summary.Class = "gate_c_request_invalid"
			var failure *Failure
			if errors.As(runErr, &failure) {
				summary.Class, summary.Stage = failure.Class, failure.Stage
			}
		}
		var interfaceWitness any
		if ownedInterface != nil {
			interfaceWitness = ownedInterface.Witness()
		}
		if err := evidence.Append(struct {
			Result    Result `json:"result"`
			Class     string `json:"class"`
			Interface any    `json:"interface"`
		}{result, summary.Class, interfaceWitness}); err != nil {
			summary.Class = ClassRequestInvalid
			runErr = errors.Join(runErr, fieldc1c.ErrInvalid)
		}
		digest, err := evidence.Seal()
		if err != nil {
			summary.Class = ClassRequestInvalid
			runErr = errors.Join(runErr, err)
		}
		summary.EvidenceSHA256 = digest
		u64 := func(n int) *uint64 { v := uint64(n); return &v }
		summary.Counts = map[string]*uint64{"evidence_packets": u64(result.Witness.GateB.Emissions.EvidencePackets),
			"candidate_packets": u64(result.Witness.GateB.Emissions.CandidatePackets), "winner_packets": u64(result.Witness.GateB.Emissions.WinnerPackets),
			"udp_opened": u64(result.Witness.GateB.Emissions.SocketsOpened), "external_socket_residue": nil, "external_conntrack_residue": nil, "external_process_residue": nil}
		if runErr != nil {
			runErr = errors.New(summary.Class)
		}
	}()
	fieldCtx, cancel := context.WithDeadline(ctx, binding.Deadline)
	defer cancel()
	machine, ledger, err := acquireMachine(artifact.PlannerProfile, artifact.ResourceClass, fieldc1c.BuildSHA)
	if err != nil {
		return summary, fieldc1c.ErrInvalid
	}
	defer machine.Close()
	input.machine, input.ledger = machine, ledger
	input.progress = func(value Progress) error {
		return evidence.Append(struct {
			Progress
			AtNS int64 `json:"at_ns"`
		}{value, time.Since(started).Nanoseconds()})
	}
	deps := defaultDependencies()
	deps.inspectConflict = fieldConflictInspector
	deps.configureGateB = func(configuration *gateb.Config) {
		if gateb.ConfigureFieldAttempt(configuration, instance, factory) != nil {
			configuration.Machine = nil
		}
	}
	deps.newInterface = func(name string, mtu int) (netif.MemoryTestInterface, error) {
		if name != peer.interfaceName || mtu != peer.mtu {
			return nil, ErrRequestInvalid
		}
		var err error
		ownedInterface, err = netif.NewFieldInterface(fieldCtx, authority)
		return ownedInterface, err
	}
	deps.newTunnel = tunnel.NewFieldWireGuard
	result, runErr = runPrepared(fieldCtx, input, deps)
	return summary, runErr
}

func loadFieldConfiguration(instance fieldc1c.Instance, path string) (*config.Config, error) {
	data, err := pairgen.ReadPrivateFile(path, 64*1024)
	if err != nil {
		return nil, fieldc1c.ErrInvalid
	}
	defer clear(data)
	if instance.CheckConfiguration(data) != nil {
		return nil, fieldc1c.ErrInvalid
	}
	// Decode the exact verified bytes, with no Viper environment overrides or
	// second file read. Defaults are inert; known YAML fields are strict.
	configuration := config.Default()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if decoder.Decode(&configuration) != nil {
		return nil, fieldc1c.ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || configuration.Validate() != nil {
		return nil, fieldc1c.ErrInvalid
	}
	return &configuration, nil
}

func validateFieldMaterial(instance fieldc1c.Instance, binding fieldc1c.Binding, request gatecrequest.Request, artifact *gatecattempt.Artifact) error {
	if artifact == nil || artifact.AttemptID != binding.ID || string(artifact.LocalRole) != binding.Role || request.Role != artifact.LocalRole ||
		string(artifact.PlannerProfile) != binding.Profile || string(artifact.ResourceClass) != binding.Resource || !artifact.ExpiresAt.Equal(binding.CredentialExpiresAt) {
		return fieldc1c.ErrInvalid
	}
	if binding.MappingSetRole != "" {
		role := artifact.InitiatorPlannerRole
		if binding.MappingSetRole == "responder" {
			role = artifact.ResponderPlannerRole
		}
		if role != hardnatplan.RoleMappingSet {
			return fieldc1c.ErrInvalid
		}
	}
	peer, observers, err := instance.Network()
	if err != nil || request.ExpectedPeerPublicAddress != peer || request.ObserverSet.Endpoints() != observers {
		return fieldc1c.ErrInvalid
	}
	device, err := instance.Device()
	if err != nil {
		return fieldc1c.ErrInvalid
	}
	approved, err := gatecrequest.LoadPrivate(device.RequestReference)
	if err != nil {
		return fieldc1c.ErrInvalid
	}
	a, e1 := gatecrequest.Encode(approved)
	b, e2 := gatecrequest.Encode(request)
	defer clear(a)
	defer clear(b)
	if e1 != nil || e2 != nil || !bytes.Equal(a, b) {
		return fieldc1c.ErrInvalid
	}
	data, err := pairgen.ReadPrivateFile(binding.ManifestReference, gatecattempt.MaxManifestBytes)
	if err != nil {
		return fieldc1c.ErrInvalid
	}
	defer clear(data)
	digest := sha256.Sum256(data)
	manifest, err := gatecattempt.ParseManifest(data)
	if err != nil || hex.EncodeToString(digest[:]) != binding.ManifestSHA256 || manifest.ArtifactFingerprint != artifact.Fingerprint ||
		manifest.AttemptID != artifact.AttemptID || manifest.CredentialID != artifact.CredentialID || manifest.OOBChannelID != artifact.OOBChannelID ||
		manifest.PlannerProfile != binding.Profile || manifest.ResourceClass != binding.Resource {
		return fieldc1c.ErrInvalid
	}
	if request.Role == gatecattempt.RoleInitiator {
		endpoint, err := instance.SSHEndpoint()
		pin, key, fileErr := instance.SSHFiles()
		if err != nil || fileErr != nil || request.SSH == nil || request.SSH.Endpoint != endpoint || request.SSH.KnownHostsFile != pin || request.SSH.IdentityFile != key {
			return fieldc1c.ErrInvalid
		}
	}
	return nil
}

func fieldConflictInspector(ctx context.Context, input preparedInput, peer trustedPeer) (conflictState, error) {
	state := conflictState{}
	if ctx == nil || ctx.Err() != nil {
		return state, ErrRequestInvalid
	}
	localOwnership.Lock()
	_, state.PrivateKeyInUse = localOwnership.keys[peer.privateKey.PublicKey()]
	_, state.InterfaceInUse = localOwnership.interfaces[peer.interfaceName]
	_, state.RouteInUse = localOwnership.routes[peer.remoteVirtual]
	localOwnership.Unlock()
	if _, err := os.Lstat(runtimeStatePath(input.configPath)); err == nil {
		state.WinkUpRunning = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return state, ErrRequestInvalid
	}
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 65536 {
		return state, ErrRequestInvalid
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "" || strings.Trim(name, "0123456789") != "" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			return state, ErrRequestInvalid
		}
		if len(data) > 65536 {
			return state, ErrRequestInvalid
		}
		args := strings.Split(string(data), "\x00")
		if len(args) > 1 && filepath.Base(args[0]) == "wink" && args[1] == "up" {
			state.WinkUpRunning = true
			return state, nil
		}
	}
	// Existing userspace WireGuard UAPI owners cannot be inspected without
	// acquiring a new socket capability. Conservatively reject their presence.
	entries, err = os.ReadDir("/var/run/wireguard")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return state, ErrRequestInvalid
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sock") {
			state.PrivateKeyInUse = true
		}
	}
	return state, nil
}
