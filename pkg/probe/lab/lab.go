package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/session/wireadapter"
	"winkyou/pkg/solver"
)

type Runner struct{}

func LoadScript(path string) (model.Script, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Script{}, err
	}
	var script rproto.ProbeScript
	if err := json.Unmarshal(data, &script); err != nil {
		return model.Script{}, fmt.Errorf("probe: decode script: %w", err)
	}
	return wireadapter.ProbeScriptFromWire(script), nil
}

func (Runner) Run(ctx context.Context, script model.Script) (model.Result, error) {
	result := model.Result{
		ScriptType: script.ScriptType,
		PlanID:     script.PlanID,
		Events:     make([]solver.Observation, 0, len(script.Steps)+1),
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
					"step_type":  step.Action,
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
	switch step.Action {
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
		return solver.Observation{}, fmt.Errorf("probe: unsupported step type %q", step.Action)
	}
}

func runUDPSend(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	timeout := stepTimeout(step.Timeout, 5*time.Second)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp4", step.Params["addr"])
	if err != nil {
		return solver.Observation{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(step.Params["payload"])); err != nil {
		return solver.Observation{}, err
	}
	return solver.Observation{
		Strategy:   model.StrategyName,
		PlanID:     planID,
		Event:      model.StepUDPSend,
		RemoteAddr: step.Params["addr"],
		Reason:     "sent",
		Details: map[string]string{
			"payload_len": fmt.Sprintf("%d", len(step.Params["payload"])),
		},
		Timestamp: time.Now(),
	}, nil
}

func runUDPListen(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	addr, err := net.ResolveUDPAddr("udp4", step.Params["addr"])
	if err != nil {
		return solver.Observation{}, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return solver.Observation{}, err
	}
	defer conn.Close()

	timeout := stepTimeout(step.Timeout, 5*time.Second)
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
		if expect := step.Params["expect"]; expect != "" && payload != expect {
			return solver.Observation{}, fmt.Errorf("probe: udp payload = %q, want %q", payload, expect)
		}
		if reply := step.Params["reply"]; reply != "" {
			if _, err := conn.WriteToUDP([]byte(reply), read.remote); err != nil {
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
	timeout := stepTimeout(step.Timeout, 5*time.Second)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp4", step.Params["addr"])
	if err != nil {
		return solver.Observation{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if message := step.Params["message"]; message != "" {
		if _, err := conn.Write([]byte(message)); err != nil {
			return solver.Observation{}, err
		}
	}
	if expect := step.Params["expect"]; expect != "" {
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return solver.Observation{}, err
		}
		if string(buf[:n]) != expect {
			return solver.Observation{}, fmt.Errorf("probe: tcp reply = %q, want %q", string(buf[:n]), expect)
		}
	}
	return solver.Observation{
		Strategy:       model.StrategyName,
		PlanID:         planID,
		Event:          model.StepTCPCheck,
		ConnectionType: "tcp",
		RemoteAddr:     step.Params["addr"],
		Reason:         "checked",
		Timestamp:      time.Now(),
	}, nil
}

func runSleep(ctx context.Context, planID string, step model.Step) (solver.Observation, error) {
	durationMS, _ := strconv.Atoi(step.Params["duration_ms"])
	duration := time.Duration(durationMS) * time.Millisecond
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
	event := step.Params["event"]
	if event == "" {
		event = "report"
	}
	return solver.Observation{
		Strategy:  model.StrategyName,
		PlanID:    planID,
		Event:     event,
		Details:   wireadapter.ProbeStepDetails(step),
		Timestamp: time.Now(),
	}
}

func stepTimeout(timeout, fallback time.Duration) time.Duration {
	if timeout <= 0 {
		return fallback
	}
	return timeout
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
