package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

type Runner struct{}

func LoadScript(path string) (model.Script, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Script{}, err
	}
	var script model.Script
	if err := json.Unmarshal(data, &script); err != nil {
		return model.Script{}, fmt.Errorf("probe: decode script: %w", err)
	}
	return script, nil
}

func (Runner) Run(ctx context.Context, script model.Script) (model.Result, error) {
	result := model.Result{
		PlanID: script.PlanID,
		Events: make([]solver.Observation, 0, len(script.Steps)+1),
	}
	for i, step := range script.Steps {
		obs, err := runStep(ctx, script.PlanID, step)
		if obs.Event != "" {
			result.Events = append(result.Events, obs)
		}
		if err != nil {
			result.Success = false
			result.ErrorClass = classifyError(err)
			result.FinishedAt = time.Now()
			result.Events = append(result.Events, solver.Observation{
				Strategy:   model.StrategyName,
				PlanID:     script.PlanID,
				Event:      "script_failed",
				ErrorClass: result.ErrorClass,
				Reason:     err.Error(),
				Details: map[string]string{
					"step_index": fmt.Sprintf("%d", i),
					"step_type":  step.Type,
				},
				Timestamp: time.Now(),
			})
			return result, err
		}
	}
	result.Success = true
	result.FinishedAt = time.Now()
	return result, nil
}

func runStep(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	switch step.Type {
	case model.StepUDPSend:
		return runUDPSend(ctx, planID, step)
	case model.StepUDPListen:
		return runUDPListen(ctx, planID, step)
	case model.StepTCPCheck:
		return runTCPCheck(ctx, planID, step)
	case model.StepSleep:
		return runSleep(ctx, planID, step)
	case model.StepReport:
		return runReport(planID, step), nil
	default:
		return solver.Observation{}, fmt.Errorf("probe: unsupported step type %q", step.Type)
	}
}

func runUDPSend(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	timeout := stepTimeout(step.TimeoutMS, 5*time.Second)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp4", step.Addr)
	if err != nil {
		return solver.Observation{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(step.Payload)); err != nil {
		return solver.Observation{}, err
	}
	return solver.Observation{
		Strategy:   model.StrategyName,
		PlanID:     planID,
		Event:      model.StepUDPSend,
		RemoteAddr: step.Addr,
		Reason:     "sent",
		Details: map[string]string{
			"payload_len": fmt.Sprintf("%d", len(step.Payload)),
		},
		Timestamp: time.Now(),
	}, nil
}

func runUDPListen(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	addr, err := net.ResolveUDPAddr("udp4", step.Addr)
	if err != nil {
		return solver.Observation{}, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return solver.Observation{}, err
	}
	defer conn.Close()

	timeout := stepTimeout(step.TimeoutMS, 5*time.Second)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	done := make(chan struct {
		n      int
		remote *net.UDPAddr
		err    error
	}, 1)
	go func() {
		n, remote, err := conn.ReadFromUDP(buf)
		done <- struct {
			n      int
			remote *net.UDPAddr
			err    error
		}{n: n, remote: remote, err: err}
	}()

	select {
	case <-ctx.Done():
		return solver.Observation{}, ctx.Err()
	case read := <-done:
		if read.err != nil {
			return solver.Observation{}, read.err
		}
		payload := string(buf[:read.n])
		if step.Expect != "" && payload != step.Expect {
			return solver.Observation{}, fmt.Errorf("probe: udp payload = %q, want %q", payload, step.Expect)
		}
		if step.Reply != "" {
			if _, err := conn.WriteToUDP([]byte(step.Reply), read.remote); err != nil {
				return solver.Observation{}, err
			}
		}
		return solver.Observation{
			Strategy:   model.StrategyName,
			PlanID:     planID,
			Event:      model.StepUDPListen,
			LocalAddr:  conn.LocalAddr().String(),
			RemoteAddr: read.remote.String(),
			Reason:     "received",
			Details: map[string]string{
				"payload_len": fmt.Sprintf("%d", read.n),
			},
			Timestamp: time.Now(),
		}, nil
	}
}

func runTCPCheck(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	timeout := stepTimeout(step.TimeoutMS, 5*time.Second)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp4", step.Addr)
	if err != nil {
		return solver.Observation{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if step.Message != "" {
		if _, err := conn.Write([]byte(step.Message)); err != nil {
			return solver.Observation{}, err
		}
	}
	if step.Expect != "" {
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return solver.Observation{}, err
		}
		if string(buf[:n]) != step.Expect {
			return solver.Observation{}, fmt.Errorf("probe: tcp reply = %q, want %q", string(buf[:n]), step.Expect)
		}
	}
	return solver.Observation{
		Strategy:       model.StrategyName,
		PlanID:         planID,
		Event:          model.StepTCPCheck,
		ConnectionType: "tcp",
		RemoteAddr:     step.Addr,
		Reason:         "checked",
		Timestamp:      time.Now(),
	}, nil
}

func runSleep(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	duration := time.Duration(step.DurationMS) * time.Millisecond
	if duration <= 0 {
		duration = 50 * time.Millisecond
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return solver.Observation{}, ctx.Err()
	case <-timer.C:
		return solver.Observation{
			Strategy:  model.StrategyName,
			PlanID:    planID,
			Event:     model.StepSleep,
			TimeoutMS: duration.Milliseconds(),
			Timestamp: time.Now(),
		}, nil
	}
}

func runReport(planID string, step model.Step) solver.Observation {
	event := step.Event
	if event == "" {
		event = "report"
	}
	return solver.Observation{
		Strategy:  model.StrategyName,
		PlanID:    planID,
		Event:     event,
		Details:   cloneDetails(step.Details),
		Timestamp: time.Now(),
	}
}

func stepTimeout(rawMS int, fallback time.Duration) time.Duration {
	if rawMS <= 0 {
		return fallback
	}
	return time.Duration(rawMS) * time.Millisecond
}

func classifyError(err error) string {
	switch err {
	case nil:
		return ""
	case context.DeadlineExceeded:
		return "timeout"
	case context.Canceled:
		return "canceled"
	default:
		return "unknown"
	}
}

func cloneDetails(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
