package gatecorchestrator

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

const (
	StagePreflight          = "preflight"
	StageSSHSpawn           = "ssh_spawn"
	StageFinishRecorded     = "finish_recorded"
	StageOOBDrained         = "oob_drained"
	StageDataPlaneReady     = "data_plane_ready"
	StageTerminal           = "terminal"
	ClassRequestInvalid     = "gate_c_request_invalid"
	ClassPeerUnauthorized   = "peer_address_not_authorized"
	ClassSSHProfileInvalid  = "ssh_profile_invalid"
	ClassSSHHostRejected    = "ssh_host_identity_rejected"
	ClassSSHUnavailable     = "ssh_transport_unavailable"
	ClassSSHChildTerminated = "ssh_child_terminated"
	ClassSSHBudgetExceeded  = "ssh_budget_exceeded"
	ClassWireGuardBinding   = "wireguard_binding_failed"
	ClassPostHandoff        = "post_handoff_validation_failed"
	ClassSessionDrain       = "session_drain_failed"
)

const (
	PostOOBEchoTimeout       = 2 * time.Second
	SessionDrainTimeout      = 2 * time.Second
	SessionActivityInterval  = 5 * time.Second
	SessionInactiveIntervals = 3
)

var ProductProgressSequence = []string{
	StagePreflight, StageSSHSpawn, gateb.StageOOBAdopt, gateb.StagePresent,
	gateb.StageBurned, gateb.StageActivated, gateb.StageHandshake, gateb.StagePrepare,
	gateb.StageSockets, gateb.StageEvidence, gateb.StagePlan, gateb.StageReady,
	gateb.StageFire, gateb.StageCandidates, gateb.StageWinner, gateb.StageVerify,
	gateb.StageTransportLease, gateb.StageHandoff, gateb.StageDataPlaneChallenge,
	StageFinishRecorded, StageOOBDrained, StageDataPlaneReady, StageTerminal,
}

type Progress struct {
	Stage           string        `json:"stage"`
	RemainingBudget time.Duration `json:"remaining_budget"`
	Cancellable     bool          `json:"cancellable"`
}

type ProgressReporter func(Progress) error

type Failure struct {
	Class            string         `json:"class"`
	Stage            string         `json:"stage"`
	CredentialBurned bool           `json:"credential_burned"`
	Retryable        bool           `json:"retryable"`
	Profile          string         `json:"profile"`
	ResourceClass    string         `json:"resource_class"`
	Counts           map[string]int `json:"counts,omitempty"`
	Cause            error          `json:"-"`
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "gatecorchestrator: terminal failure"
	}
	return "gatecorchestrator: " + failure.Class
}

func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

type EchoWitness struct {
	RequestsWritten  int  `json:"requests_written"`
	RequestsRead     int  `json:"requests_read"`
	ResponsesWritten int  `json:"responses_written"`
	ResponsesRead    int  `json:"responses_read"`
	CloseWritten     int  `json:"close_written"`
	CloseRead        int  `json:"close_read"`
	ReplaysRejected  int  `json:"replays_rejected"`
	Drained          bool `json:"drained"`
}

type Witness struct {
	SSH             sshassembly.Witness                 `json:"ssh"`
	GateB           gateb.Result                        `json:"gate_b"`
	Handoff         gateb.ProductHandoffWitness         `json:"handoff"`
	WireGuard       probeio.WireGuardSessionGateWitness `json:"wireguard"`
	Echo            EchoWitness                         `json:"echo"`
	InterfaceClosed bool                                `json:"interface_closed"`
	TunnelStopped   bool                                `json:"tunnel_stopped"`
}

type Result struct {
	Terminal         string  `json:"terminal"`
	DataPlaneReady   bool    `json:"data_plane_ready"`
	CredentialBurned bool    `json:"credential_burned"`
	FinishRecorded   bool    `json:"finish_recorded"`
	SessionEnd       string  `json:"session_end"`
	Witness          Witness `json:"witness"`
}

type InitiatorOptions struct {
	RequestFile  string
	Config       *config.Config
	ConfigPath   string
	BuildVersion string
	Progress     ProgressReporter
}

type ResponderOptions struct {
	Config       *config.Config
	ConfigPath   string
	BuildVersion string
	Progress     ProgressReporter
}

type sshProductStream interface {
	oobcarrier.BoundedStream
	Witness() sshassembly.Witness
	TerminalError() error
}

type preparedInput struct {
	request       gatecrequest.Request
	artifact      *gatecattempt.Artifact
	configuration *config.Config
	configPath    string
	buildVersion  string
	machine       *governor.Governor
	ledger        *governor.PairingAdmissionLedger
	sshAuthority  sshassembly.SSHEndpointAuthority
	stream        oobcarrier.BoundedStream
	childInput    io.Reader
	childOutput   io.Writer
	progress      ProgressReporter
}

type trustedPeer struct {
	ref            string
	privateKey     tunnel.PrivateKey
	publicKey      tunnel.PublicKey
	allowedIPs     []netip.Prefix
	localVirtual   netip.Addr
	remoteVirtual  netip.Addr
	interfaceName  string
	mtu            int
	sessionCeiling time.Duration
}

type conflictState struct {
	WinkUpRunning   bool
	PrivateKeyInUse bool
	InterfaceInUse  bool
	RouteInUse      bool
}

type dependencies struct {
	now              func() time.Time
	random           io.Reader
	configureGateB   func(*gateb.Config)
	inspectConflict  func(context.Context, preparedInput, trustedPeer) (conflictState, error)
	openSSH          func(context.Context, sshassembly.Config) (sshProductStream, error)
	claimPending     func(time.Time) (*gatecstage.Claimed, error)
	acquireMachine   func(hardnatplan.Profile, hardnatplan.ResourceClass, string) (*governor.Governor, *governor.PairingAdmissionLedger, error)
	newChildStream   func(io.Reader, io.Writer, time.Time) (oobcarrier.BoundedStream, error)
	newInterface     func(string, int) (netif.MemoryTestInterface, error)
	newTunnel        func(tunnel.Config) (tunnel.Tunnel, error)
	activityInterval time.Duration
}

var (
	ErrRequestInvalid   = errors.New("gatecorchestrator: local request is invalid")
	ErrPeerUnauthorized = errors.New("gatecorchestrator: peer address is not authorized")
	ErrWireGuardBinding = errors.New("gatecorchestrator: WireGuard binding failed")
	ErrPostHandoff      = errors.New("gatecorchestrator: post-handoff validation failed")
	ErrSessionDrain     = errors.New("gatecorchestrator: session drain failed")
)
