//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"winkyou/internal/v2/fieldc1c"
)

func runOwned(ctx context.Context, a fieldc1c.RouterAuthority, j *journal) (summary Summary) {
	started := time.Now()
	s, e := a.Snapshot()
	summary = Summary{Profile: s.Profile, Stage: "preflight", Class: "gate_c_request_invalid"}
	if e != nil || a.Check(started) != nil {
		return summary
	}
	t := &topology{snapshot: s, journal: j}
	var routers [2]*natRouter
	var observer *observerSet
	var sampleWorker *sampler
	var output *evidence
	var failure error
	defer func() {
		// All I/O stops before namespace cleanup. Endpoint FINISH/release is
		// not owned here; this tool cannot refund or reset its credentials.
		drainErr := drainOwned(routers, observer, sampleWorker)
		failure = errors.Join(failure, drainErr)
		for _, r := range routers {
			if r != nil {
				summary.Counts.Outbound += r.out.Load()
				summary.Counts.Inbound += r.in.Load()
				summary.Counts.PeakMappings += r.peak.Load()
				summary.Counts.Censored += r.dropped.Load()
			}
		}
		if observer != nil {
			summary.Counts.ObserverReplies = observer.replies.Load()
		}
		if sampleWorker != nil {
			summary.Counts.Queries = sampleWorker.queries.Load()
			summary.Counts.Unknown = sampleWorker.unknown.Load()
		}
		failure = errors.Join(failure, t.cleanup(&summary.Counts))
		if drainErr != nil {
			summary.Counts.SocketResidue = nil
		}
		// The worker cannot witness its own process exit. Only its separate
		// guardian sets this field after Wait has reaped the exact child.
		summary.Counts.ProcessResidue = nil
		if output != nil {
			for _, role := range []string{"initiator", "responder"} {
				row := unknownObservation(role, "terminal-correlation-pending")
				failure = errors.Join(failure, output.append(row, true))
			}
			failure = errors.Join(failure, output.append(summary.Counts, true))
			hash, err := output.seal()
			summary.EvidenceSHA256 = hash
			failure = errors.Join(failure, err)
		}
		if failure != nil {
			summary.Class = errorClass(failure)
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			summary.Class = "expired"
		} else {
			summary.Class = "cancelled"
		}
		summary.Stage = "terminal"
		summary.DurationNS = time.Since(started).Nanoseconds()
	}()
	output, e = openEvidence(s.Directory, "router.jsonl")
	if e != nil {
		failure = e
		return summary
	}
	if e = t.create(ctx); e != nil {
		failure = e
		return summary
	}
	samples := make(chan mappingSample, QueueCapacity)
	var budget atomic.Uint64
	for i, d := range s.Configuration.Domains {
		peer := netip.MustParsePrefix(s.Configuration.Domains[1-i].PublicPrefix).Addr()
		routers[i], e = newNAT(ctx, t.owned[i], d, peer, s.Observers, samples, s.ID, &budget)
		if e != nil {
			failure = e
			return summary
		}
		if e = t.configureTUN(ctx, i); e != nil {
			failure = e
			return summary
		}
	}
	sources := [2]netip.Addr{netip.MustParsePrefix(s.Configuration.Domains[0].PublicPrefix).Addr(), netip.MustParsePrefix(s.Configuration.Domains[1].PublicPrefix).Addr()}
	observer, e = newObserver(ctx, t.anchors[1], s.Observers, sources)
	if e != nil {
		failure = e
		return summary
	}
	sampleWorker = startSampler(ctx, s.Namespaces, samples, output)
	for _, r := range routers {
		r.start()
	}
	if a.Check(time.Now()) != nil {
		failure = ErrInvalid
		return summary
	}
	summary.Stage = "router_ready"
	if e = output.append(struct {
		Stage string `json:"stage"`
	}{summary.Stage}, true); e != nil {
		failure = e
		return summary
	}
	if e = writePrivateJSON(s.Directory, "ready.json", struct {
		Stage string `json:"stage"`
	}{summary.Stage}); e != nil {
		failure = e
		return summary
	}
	select {
	case <-ctx.Done():
	case failure = <-observer.failure:
	case failure = <-routers[0].done:
		routers[0].started = false
	case failure = <-routers[1].done:
		routers[1].started = false
	case failure = <-sampleWorker.done:
		sampleWorker.done <- nil
	}
	return summary
}

func drainOwned(routers [2]*natRouter, observer *observerSet, sampleWorker *sampler) error {
	// One absolute tool drain envelope, not a fresh 2s per component.
	timer := time.NewTimer(DrainTimeout)
	defer timer.Stop()
	finished := make(chan error, 4)
	count := 0
	for _, r := range routers {
		if r != nil {
			r.cancel()
			count++
			go func(r *natRouter) { finished <- r.close() }(r)
		}
	}
	if observer != nil {
		observer.cancel()
		count++
		go func() { finished <- observer.close() }()
	}
	if sampleWorker != nil {
		sampleWorker.cancel()
		count++
		go func() { finished <- sampleWorker.close() }()
	}
	var failure error
	for i := 0; i < count; i++ {
		select {
		case e := <-finished:
			failure = errors.Join(failure, e)
		case <-timer.C:
			return errors.Join(failure, ErrDrain)
		}
	}
	return failure
}

func writePrivateJSON(dir, name string, value any) error {
	if privateDirectory(dir) != nil {
		return ErrOwnership
	}
	b, e := json.Marshal(value)
	if e != nil {
		return ErrInvalid
	}
	defer clear(b)
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return ErrOwnership
	}
	n, e := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil || n != len(b) || syncErr != nil || closeErr != nil {
		return errIO
	}
	return syncDir(dir)
}
