package gatecorchestrator

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

const livenessPoll = 25 * time.Millisecond

// The reporter carries immutable, already-authenticated local binding. It
// cannot choose a new owner/target or report through a released AttemptLease.
type livenessReporter struct {
	mu              sync.Mutex
	machine         *governor.Governor
	attempt, build  string
	closed, tripped bool
}

func (r *livenessReporter) report(v probeio.SessionViolation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.machine == nil {
		return errLivenessUnavailable
	}
	if r.tripped {
		return nil
	}
	reason, detail := governor.SafetyTripHardLimit, "Gate C active session admission bypass"
	switch v {
	case probeio.SessionAdmissionBypass:
	case probeio.SessionControlLimit:
		detail = "Gate C active automatic control limit exceeded"
	case probeio.SessionControlInvalid:
		detail = "Gate C invalid automatic control packet"
	case probeio.SessionWriterFailure:
		reason, detail = governor.SafetyTripWriteFailures, "Gate C active session writer failed"
	case probeio.SessionDrainFailure:
		reason, detail = governor.SafetyTripCancellation, "Gate C active session drain failed"
	default:
		return errLivenessUnavailable
	}
	status, err := r.machine.Trip(governor.SafetyTripEvent{Reason: reason, Detail: detail, AttemptID: r.attempt, BuildVersion: r.build})
	if err != nil || !status.BlocksActiveWork || status.State != governor.SafetyTripTripped {
		return errLivenessUnavailable
	}
	r.tripped = true
	return nil
}
func (r *livenessReporter) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.machine = nil
}

func (r *livenessReporter) available() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.machine == nil {
		return errLivenessUnavailable
	}
	if r.tripped {
		return nil
	} // the triggering failure retains its precise class
	snapshot := r.machine.Snapshot()
	if snapshot.Closed || snapshot.SafetyTrip.BlocksActiveWork {
		return errLivenessUnavailable
	}
	return nil
}

type livenessControlEvent struct {
	packet [livenessPacketSize]byte
	length int
}

type livenessController struct {
	model                    *livenessModel
	ni                       netif.MemoryTestInterface
	gate                     *probeio.WireGuardSessionGate
	random                   io.Reader
	reportViolation          func(probeio.SessionViolation) error
	ownerAvailable           func() error
	inboundDrops             atomic.Uint64
	ingress                  sync.Mutex // TryLock in Deliver: never blocks the decrypt path
	stop                     chan struct{}
	writerDone, watchdogDone chan struct{}
	stopOnce                 sync.Once
	inbound                  chan livenessControlEvent
	outbound                 chan *livenessEmission
	closeWrites, closeReads  int // foreground-owned, never emitted periodically
}

func armLiveness(model *livenessModel, ni netif.MemoryTestInterface, tun tunnel.Tunnel, gate *probeio.WireGuardSessionGate, random io.Reader, report func(probeio.SessionViolation) error, available func() error) (*livenessController, error) {
	registrar, ok := tun.(tunnel.InnerTapRegistrar)
	if !ok || ni == nil || gate == nil || model == nil || random == nil || report == nil || available == nil {
		return nil, errLivenessUnavailable
	}
	c := &livenessController{model: model, ni: ni, gate: gate, random: random, reportViolation: report, ownerAvailable: available,
		stop: make(chan struct{}), writerDone: make(chan struct{}), watchdogDone: make(chan struct{}), inbound: make(chan livenessControlEvent, 2), outbound: make(chan *livenessEmission, 2)}
	if err := c.permit(); err != nil {
		return nil, err
	}
	if err := gate.ArmActivePolicy(probeio.ActiveSessionPolicy{Ceiling: model.budget.ceiling, Permit: c.permit, Elapsed: model.currentMonotonicElapsed, Report: c.hardViolation}); err != nil {
		return nil, errLivenessUnavailable
	}
	b := model.binding
	tuples := []tunnel.InnerTuple{
		{Src: b.Remote, Dst: b.Local, Proto: 17, SrcPort: livenessPort, DstPort: livenessPort},
		{Src: b.Remote, Dst: b.Local, Proto: 17, SrcPort: echoPort, DstPort: echoPort},
	}
	if err := registrar.SetInnerTap(tuples, c); err != nil {
		_ = gate.Close()
		return nil, errLivenessUnavailable
	}
	go c.writer()
	go c.watchdog()
	return c, nil
}

// Deliver is called on WireGuard's decrypted ingress, not on a competing TUN
// reader. Oversize is represented as an invalid event without copying bytes.
func (c *livenessController) Deliver(packet []byte) bool {
	if !c.ingress.TryLock() {
		c.inboundDrops.Add(1)
		return false
	}
	defer c.ingress.Unlock()
	select {
	case <-c.stop:
		return false
	default:
	}
	e := livenessControlEvent{length: len(packet)}
	if len(packet) <= len(e.packet) {
		copy(e.packet[:], packet)
	}
	select {
	case c.inbound <- e:
		return true
	default:
		c.inboundDrops.Add(1)
		return false
	}
}

func (c *livenessController) permit() error {
	if err := c.ownerAvailable(); err != nil {
		c.model.mu.Lock()
		if c.model.terminal == nil {
			c.model.terminal = errLivenessUnavailable
		}
		c.model.mu.Unlock()
		return errLivenessUnavailable
	}
	return c.model.permit()
}

func (c *livenessController) end(err error) {
	c.model.mu.Lock()
	if c.model.terminal == nil && err != nil {
		c.model.terminal = err
	}
	c.model.closed = true
	c.model.mu.Unlock()
	c.stopOnce.Do(func() { close(c.stop); _ = c.gate.Close(); _ = c.ni.Close() })
}

func (c *livenessController) hardViolation(v probeio.SessionViolation) error {
	err := c.reportViolation(v)
	if err != nil {
		c.end(errLivenessUnavailable)
		return errLivenessUnavailable
	}
	terminal := ErrSessionDrain
	switch v {
	case probeio.SessionAdmissionBypass, probeio.SessionControlLimit:
		terminal = errLivenessBudget
	case probeio.SessionControlInvalid:
		terminal = errLivenessProtocol
	}
	c.end(terminal)
	return terminal
}

func (c *livenessController) enqueue(e *livenessEmission) {
	if e == nil {
		return
	}
	select {
	case <-c.stop:
		c.model.discard(e)
	case c.outbound <- e:
	default:
		c.model.discard(e)
	}
}

func (c *livenessController) writer() {
	defer close(c.writerDone)
	for {
		select {
		case <-c.stop:
			return
		case e := <-c.outbound:
			if err := c.permit(); err != nil {
				c.end(err)
				return
			}
			allowed, err := c.model.beginWrite(e)
			if err != nil {
				if errors.Is(err, errLivenessBudget) {
					_ = c.hardViolation(probeio.SessionAdmissionBypass)
				} else {
					c.end(err)
				}
				return
			}
			if !allowed {
				clear(e.packet)
				continue
			}
			want := len(e.packet)
			n, err := c.ni.InjectPacket(e.packet)
			c.model.endWrite(err == nil && n == want && !e.teardown)
			clear(e.packet)
			if err != nil || n != want {
				select {
				case <-c.stop:
					return
				default:
				}
				c.model.mu.Lock()
				c.model.witness.WriterFailures++
				c.model.mu.Unlock()
				_ = c.hardViolation(probeio.SessionWriterFailure)
				return
			}
		}
	}
}

func (c *livenessController) watchdog() {
	defer close(c.watchdogDone)
	timer := time.NewTicker(livenessPoll)
	defer timer.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-timer.C:
		}
		if err := c.permit(); err != nil {
			c.end(err)
			return
		}
		c.model.mu.Lock()
		stalled, clockErr := false, error(nil)
		if c.model.writing {
			stalled, clockErr = c.model.windowExpiredLocked(c.model.writeWindow)
		}
		c.model.mu.Unlock()
		if clockErr != nil {
			c.end(clockErr)
			return
		}
		if stalled {
			_ = c.hardViolation(probeio.SessionWriterFailure)
			return
		}
	}
}

func (c *livenessController) run(ctx, session context.Context) (string, error) {
	timer := time.NewTicker(livenessPoll)
	defer timer.Stop()
	for {
		if err := c.permit(); err != nil {
			c.end(err)
			return livenessEnd(err)
		}
		select {
		case <-c.stop:
			c.model.mu.Lock()
			err := c.model.terminal
			c.model.mu.Unlock()
			return livenessEnd(err)
		case <-session.Done():
			c.end(session.Err())
			return "absolute_ceiling", nil
		case <-ctx.Done():
			c.bestEffortClose(timer.C)
			c.end(nil)
			if c.closeWrites != 0 {
				return "authenticated_close_sent", nil
			}
			return "canceled", nil
		case event := <-c.inbound:
			if err := c.permit(); err != nil {
				c.end(err)
				return livenessEnd(err)
			}
			if event.length == echoPacketSize && binary.BigEndian.Uint16(event.packet[22:24]) == echoPort {
				if _, err := parseEchoPacket(event.packet[:event.length], c.model.binding, echoClose, nil); err == nil {
					c.closeReads++
					c.end(nil)
					return "authenticated_close", nil
				}
				continue
			}
			if event.length != livenessPacketSize {
				c.end(errLivenessProtocol)
				return "liveness_failed", errLivenessProtocol
			}
			e, err := c.model.receive(event.packet[:])
			if err != nil {
				c.end(err)
				return livenessEnd(err)
			}
			c.enqueue(e)
		case <-timer.C:
			sequence, err := c.model.preparePing()
			if err != nil {
				c.end(err)
				return livenessEnd(err)
			}
			if sequence == 0 {
				continue
			}
			var nonce [16]byte
			if _, err := io.ReadFull(c.random, nonce[:]); err != nil {
				c.end(errLivenessProtocol)
				return "liveness_failed", errLivenessProtocol
			}
			e, err := c.model.ping(sequence, nonce)
			clear(nonce[:])
			if err != nil {
				if errors.Is(err, errLivenessBudget) {
					err = c.hardViolation(probeio.SessionAdmissionBypass)
				} else {
					c.end(err)
				}
				return livenessEnd(err)
			}
			c.enqueue(e)
		}
	}
}

func livenessEnd(err error) (string, error) {
	switch {
	case errors.Is(err, errLivenessTimeout):
		return "liveness_timeout", err
	case errors.Is(err, context.DeadlineExceeded):
		return "absolute_ceiling", nil
	case errors.Is(err, context.Canceled), err == nil:
		return "canceled", nil
	default:
		return "liveness_failed", err
	}
}

// Original WYCE only; one best-effort teardown event, never a liveness renewal.
func (c *livenessController) bestEffortClose(ticks <-chan time.Time) {
	if c.permit() != nil {
		return
	}
	var nonce [8]byte
	if _, err := io.ReadFull(c.random, nonce[:]); err != nil {
		return
	}
	packet, err := buildEchoPacket(c.model.binding, echoClose, nonce)
	clear(nonce[:])
	if err != nil {
		return
	}
	c.model.mu.Lock()
	if err := c.model.checkLocked(); err != nil {
		c.model.mu.Unlock()
		clear(packet)
		return
	}
	e := &livenessEmission{packet: packet, window: livenessEmissionWindow{sent: c.model.clock.instant(), proofSent: c.model.proofSent}, teardown: true}
	placed := false
	for i, intent := range c.model.intents {
		if intent == nil {
			c.model.intents[i] = e
			placed = true
			break
		}
	}
	c.model.mu.Unlock()
	if !placed {
		return
	}
	before := c.gate.Witness().ActiveWrites
	c.enqueue(e)
	for {
		if c.permit() != nil {
			return
		}
		c.model.mu.Lock()
		expired, err := c.model.windowExpiredLocked(e.window)
		c.model.mu.Unlock()
		if expired || err != nil {
			return
		}
		if c.gate.Witness().ActiveWrites > before {
			c.closeWrites++
			return
		}
		select {
		case <-c.stop:
			return
		case <-ticks:
		}
	}
}

func (c *livenessController) drain() error {
	c.end(nil)
	timer := time.NewTimer(SessionDrainTimeout)
	defer timer.Stop()
	for _, done := range []<-chan struct{}{c.writerDone, c.watchdogDone} {
		select {
		case <-done:
		case <-timer.C:
			_ = c.hardViolation(probeio.SessionDrainFailure)
			return ErrSessionDrain
		}
	}
	// Join any callback which passed the stop check before revocation. New
	// callbacks drop without blocking, and cannot enqueue after this drain.
	c.ingress.Lock()
	defer c.ingress.Unlock()
	for {
		select {
		case <-c.inbound:
		default:
			goto inboundEmpty
		}
	}
inboundEmpty:
	for {
		select {
		case e := <-c.outbound:
			c.model.discard(e)
		default:
			goto outboundEmpty
		}
	}
outboundEmpty:
	c.model.mu.Lock()
	defer c.model.mu.Unlock()
	for i, e := range c.model.intents {
		if e != nil {
			clear(e.packet)
			c.model.intents[i] = nil
		}
	}
	c.model.pending = pendingLiveness{}
	c.model.witness.InboundDropped = c.inboundDrops.Load()
	c.model.witness.Drained = true
	return nil
}
