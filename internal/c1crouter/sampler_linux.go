//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"
)

type sampler struct {
	ctx              context.Context
	cancel           context.CancelFunc
	namespaces       [2]string
	input            <-chan mappingSample
	output           *evidence
	queries, unknown atomic.Uint64
	done             chan error
}

var routerClockOrigin = time.Now()

func startSampler(ctx context.Context, namespaces [2]string, input <-chan mappingSample, output *evidence) *sampler {
	child, cancel := context.WithCancel(ctx)
	s := &sampler{ctx: child, cancel: cancel, namespaces: namespaces, input: input, output: output, done: make(chan error, 1)}
	go func() { s.done <- s.run() }()
	return s
}
func (s *sampler) run() error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var latest [2]*mappingSample
	consecutive := 0
	for {
		select {
		case <-s.ctx.Done():
			return nil
		case sample := <-s.input:
			index := 0
			if sample.role == "responder" {
				index = 1
			}
			latest[index] = &sample
		case <-ticker.C:
			for i, p := range latest {
				if p == nil {
					continue
				}
				latest[i] = nil
				query, cancel := context.WithTimeout(s.ctx, QueryTimeout)
				output, err := runCommand(query, s.namespaces[i], "conntrack", nil, "-G", "-p", "udp", "--orig-src", p.remote.Addr().String(), "--orig-dst", p.local.Addr().String(), "--sport", strconv.Itoa(int(p.remote.Port())), "--dport", strconv.Itoa(int(p.local.Port())))
				state, classified := classifyQuery(query, output, err)
				cancel()
				clear(output)
				s.queries.Add(1)
				row := unknownObservation(p.role, p.ref)
				row.KernelFlowObservation = state
				if state == "unknown" {
					s.unknown.Add(1)
					row.MissingReason["kernel_flow_observation"] = "query_indeterminate"
				} else {
					delete(row.MissingReason, "kernel_flow_observation")
				}
				if !row.Valid() {
					return ErrInvalid
				}
				// Private raw tuple/time evidence permits later endpoint-side
				// correlation without manufacturing an authenticated milestone.
				raw := struct {
					Observation Observation `json:"observation"`
					Local       string      `json:"local"`
					Remote      string      `json:"remote"`
					CreatedNS   int64       `json:"created_ns"`
					LastNS      int64       `json:"last_ns"`
					ObservedNS  int64       `json:"observed_ns"`
				}{row, p.local.String(), p.remote.String(), p.created.Sub(routerClockOrigin).Nanoseconds(), p.last.Sub(routerClockOrigin).Nanoseconds(), p.observed.Sub(routerClockOrigin).Nanoseconds()}
				if e := s.output.append(raw, false); e != nil {
					return e
				}
				if errors.Is(classified, ErrCommandUnavailable) {
					return classified
				}
				if classified == nil || errors.Is(classified, context.Canceled) || errors.Is(classified, context.DeadlineExceeded) {
					consecutive = 0
				} else {
					consecutive++
				}
				if consecutive >= MaxConsecutiveQueryErrors {
					return ErrQuery
				}
			}
		}
	}
}
func (s *sampler) close() error {
	s.cancel()
	select {
	case e := <-s.done:
		return e
	case <-time.After(DrainTimeout):
		return ErrDrain
	}
}
