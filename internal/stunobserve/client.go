package stunobserve

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/pkg/solver"
)

const (
	InitialRTO              = 500 * time.Millisecond
	MaxTransmissions        = 3
	MaxObservationDuration  = 4 * time.Second
	ObservationStrategy     = "stun_observe"
	ErrorClassTimeout       = "timeout"
	ErrorClassProtocol      = "protocol_error"
	ErrorClassSource        = "source_mismatch"
	ErrorClassCancelled     = "cancelled"
	ErrorClassBudget        = "budget_rejected"
	ErrorClassInvalidTarget = "invalid_target"
	ErrorClassIO            = "io_error"
)

var (
	ErrInvalidConfig      = errors.New("stunobserve: invalid configuration")
	ErrInsufficientBudget = errors.New("stunobserve: attempt budget does not cover the declared worst case")
	ErrAlreadyObserved    = errors.New("stunobserve: client is single-use")
	ErrInvalidTarget      = errors.New("stunobserve: target must be a loopback UDP endpoint")
	ErrSourceMismatch     = errors.New("stunobserve: response source does not match the registered target")
	ErrTimeout            = errors.New("stunobserve: binding observation timed out")
)

// WorstCaseCost returns the complete reservation required before constructing
// a Client. Runtime configuration may not lower any member for this operation.
func WorstCaseCost() governor.AttemptCost {
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          1,
			Targets:          1,
			PacketsPerSecond: 2,
			Packets:          MaxTransmissions,
			FiveTuples:       1,
		},
		Duration: MaxObservationDuration,
	}
}

// Config supplies an already admitted attempt to the socket-free observer.
// Factory is invoked only by probeio after the controller has reserved a
// socket. New always obtains the transaction ID from crypto/rand.Reader.
type Config struct {
	Lease              probeio.AttemptLease
	Generation         probeio.GenerationSource
	ExpectedGeneration uint64
	Factory            probeio.Factory
	BuildVersion       string
}

// Client performs exactly one bounded Binding observation.
type Client struct {
	controller  *probeio.Controller
	now         func() time.Time
	initialRTO  time.Duration
	request     []byte
	transaction transactionID

	mu   sync.Mutex
	used bool
}

// New validates the pre-reserved worst-case budget without opening a socket.
func New(config Config) (*Client, error) {
	return newClient(config, rand.Reader, time.Now, InitialRTO)
}

func newClient(config Config, random io.Reader, now func() time.Time, initialRTO time.Duration) (*Client, error) {
	if config.Lease == nil || config.Generation == nil || config.Factory == nil || random == nil || now == nil || initialRTO <= 0 {
		return nil, fmt.Errorf("%w: lease, generation, factory, random source, clock, and RTO are required", ErrInvalidConfig)
	}
	if err := coversWorstCase(config.Lease.Request().Cost, WorstCaseCost()); err != nil {
		return nil, err
	}
	request, transaction, err := newBindingRequest(random)
	if err != nil {
		return nil, err
	}
	controller, err := probeio.New(probeio.Config{
		Lease:              config.Lease,
		Generation:         config.Generation,
		ExpectedGeneration: config.ExpectedGeneration,
		Factory:            config.Factory,
		BuildVersion:       config.BuildVersion,
		Now:                now,
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		controller:  controller,
		now:         now,
		initialRTO:  initialRTO,
		request:     request,
		transaction: transaction,
	}, nil
}

// Close releases the controller and its attempt. It is safe to call more than
// once and does not expose or promote the underlying socket.
func (client *Client) Close() error {
	if client == nil || client.controller == nil {
		return nil
	}
	return client.controller.Close()
}

// Observe performs one Binding observation and then closes the complete
// probeio attempt. The returned Observation always describes this time window;
// on failure it carries a stable ErrorClass and Reason in addition to err.
func (client *Client) Observe(ctx context.Context, target netip.AddrPort) (solver.Observation, error) {
	startedAt := time.Now().UTC()
	if client != nil && client.now != nil {
		startedAt = client.now().UTC()
	}
	observation := solver.Observation{
		Strategy:   ObservationStrategy,
		Event:      "stun_binding_observation",
		RemoteAddr: target.String(),
		TimeoutMS:  MaxObservationDuration.Milliseconds(),
		Timestamp:  startedAt,
		Details: map[string]string{
			"window_started_at": startedAt.Format(time.RFC3339Nano),
			"max_transmissions": strconv.Itoa(MaxTransmissions),
			"observation_scope": "time_window_only",
		},
	}
	finish := func(sent int, mapped netip.AddrPort, attribute string, err error) (solver.Observation, error) {
		finishedAt := time.Now().UTC()
		if client != nil && client.now != nil {
			finishedAt = client.now().UTC()
		}
		observation.Timestamp = finishedAt
		observation.Details["window_finished_at"] = finishedAt.Format(time.RFC3339Nano)
		observation.Details["transmissions"] = strconv.Itoa(sent)
		if mapped.IsValid() {
			observation.Details["mapped_address"] = mapped.String()
			observation.Details["mapped_attribute"] = attribute
		}
		if err != nil {
			observation.ErrorClass, observation.Reason = classifyError(err)
		}
		return solver.NormalizeObservation(observation), err
	}

	if client == nil || client.controller == nil || ctx == nil {
		return finish(0, netip.AddrPort{}, "", ErrInvalidConfig)
	}
	client.mu.Lock()
	if client.used {
		client.mu.Unlock()
		return finish(0, netip.AddrPort{}, "", ErrAlreadyObserved)
	}
	client.used = true
	client.mu.Unlock()
	defer client.Close()

	canonical, err := canonicalLoopbackTarget(target)
	if err != nil {
		return finish(0, netip.AddrPort{}, "", err)
	}
	observation.RemoteAddr = canonical.String()
	operationCtx, cancel := context.WithTimeout(ctx, MaxObservationDuration)
	defer cancel()

	socket, err := client.controller.OpenProbeSocket(operationCtx)
	if err != nil {
		return finish(0, netip.AddrPort{}, "", err)
	}
	defer socket.Close()
	local, err := socket.LocalAddr()
	if err != nil {
		return finish(0, netip.AddrPort{}, "", err)
	}
	observation.LocalAddr = local.String()
	if err := socket.RegisterTarget(canonical); err != nil {
		return finish(0, netip.AddrPort{}, "", err)
	}

	buffer := make([]byte, maxSTUNMessageBytes+1)
	transmissions := 0
	for attempt := 0; attempt < MaxTransmissions; attempt++ {
		if err := socket.SendProbe(operationCtx, canonical, client.request); err != nil {
			return finish(transmissions, netip.AddrPort{}, "", err)
		}
		transmissions++

		rto := client.initialRTO << attempt
		receiveCtx, receiveCancel := context.WithTimeout(operationCtx, rto)
		var mapped netip.AddrPort
		var attribute string
		_, _, receiveErr := socket.ReceiveReply(receiveCtx, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != canonical {
				return ErrSourceMismatch
			}
			var parseErr error
			mapped, attribute, parseErr = parseBindingSuccess(packet, client.transaction)
			return parseErr
		})
		receiveCancel()
		if receiveErr == nil {
			return finish(transmissions, mapped, attribute, nil)
		}
		if errors.Is(receiveErr, probeio.ErrUnregisteredTarget) || errors.Is(receiveErr, ErrSourceMismatch) {
			return finish(transmissions, netip.AddrPort{}, "", ErrSourceMismatch)
		}
		if errors.Is(receiveErr, context.DeadlineExceeded) {
			if err := ctx.Err(); err != nil {
				return finish(transmissions, netip.AddrPort{}, "", err)
			}
			if err := operationCtx.Err(); err != nil {
				return finish(transmissions, netip.AddrPort{}, "", ErrTimeout)
			}
			continue
		}
		return finish(transmissions, netip.AddrPort{}, "", unwrapReplyError(receiveErr))
	}
	return finish(transmissions, netip.AddrPort{}, "", ErrTimeout)
}

func coversWorstCase(actual, required governor.AttemptCost) error {
	resources := actual.Resources
	want := required.Resources
	if resources.Sockets < want.Sockets ||
		resources.Targets < want.Targets ||
		resources.PacketsPerSecond < want.PacketsPerSecond ||
		resources.Packets < want.Packets ||
		resources.FiveTuples < want.FiveTuples ||
		actual.Duration < required.Duration ||
		actual.Heavyweight {
		return ErrInsufficientBudget
	}
	return nil
}

func canonicalLoopbackTarget(target netip.AddrPort) (netip.AddrPort, error) {
	if !target.IsValid() || target.Port() == 0 || target.Addr().Zone() != "" {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	address := target.Addr().Unmap()
	if !address.IsLoopback() {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	return netip.AddrPortFrom(address, target.Port()), nil
}

func unwrapReplyError(err error) error {
	for _, candidate := range []error{
		ErrMessageTooLarge,
		ErrTruncatedMessage,
		ErrUnexpectedMessage,
		ErrMagicCookieMismatch,
		ErrTransactionMismatch,
		ErrAttributeLength,
		ErrUnknownRequiredAttribute,
		ErrUnsupportedAttribute,
		ErrMappedAddressMissing,
		ErrMappedAddressInvalid,
	} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return err
}

func classifyError(err error) (string, string) {
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return ErrorClassTimeout, "binding_timeout"
	case errors.Is(err, context.Canceled):
		return ErrorClassCancelled, "cancelled"
	case errors.Is(err, ErrSourceMismatch), errors.Is(err, probeio.ErrUnregisteredTarget):
		return ErrorClassSource, "response_source_mismatch"
	case errors.Is(err, ErrInvalidTarget):
		return ErrorClassInvalidTarget, "loopback_target_required"
	case errors.Is(err, ErrInsufficientBudget), errors.Is(err, probeio.ErrHardLimit):
		return ErrorClassBudget, "declared_budget_unavailable"
	case errors.Is(err, ErrMessageTooLarge),
		errors.Is(err, ErrTruncatedMessage),
		errors.Is(err, ErrUnexpectedMessage),
		errors.Is(err, ErrMagicCookieMismatch),
		errors.Is(err, ErrTransactionMismatch),
		errors.Is(err, ErrAttributeLength),
		errors.Is(err, ErrUnknownRequiredAttribute),
		errors.Is(err, ErrUnsupportedAttribute),
		errors.Is(err, ErrMappedAddressMissing),
		errors.Is(err, ErrMappedAddressInvalid):
		return ErrorClassProtocol, protocolReason(err)
	default:
		return ErrorClassIO, "probe_io_failed"
	}
}

func protocolReason(err error) string {
	switch {
	case errors.Is(err, ErrMessageTooLarge):
		return "message_too_large"
	case errors.Is(err, ErrTruncatedMessage):
		return "truncated_message"
	case errors.Is(err, ErrUnexpectedMessage):
		return "unexpected_message_type"
	case errors.Is(err, ErrMagicCookieMismatch):
		return "magic_cookie_mismatch"
	case errors.Is(err, ErrTransactionMismatch):
		return "transaction_id_mismatch"
	case errors.Is(err, ErrAttributeLength):
		return "attribute_length_invalid"
	case errors.Is(err, ErrUnknownRequiredAttribute):
		return "unknown_required_attribute"
	case errors.Is(err, ErrUnsupportedAttribute):
		return "unsupported_attribute"
	case errors.Is(err, ErrMappedAddressMissing):
		return "mapped_address_missing"
	case errors.Is(err, ErrMappedAddressInvalid):
		return "mapped_address_invalid"
	default:
		return "protocol_error"
	}
}
