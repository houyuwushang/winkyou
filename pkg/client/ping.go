package client

import (
	"fmt"
	"net"
	"time"
)

const PingPort = 33434

type PingRequest struct {
	ID string `json:"id"`
}

type PingResponse struct {
	ID string `json:"id"`
}

type pingEnvelope struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func MarshalPingRequest(request PingRequest) ([]byte, error) {
	if request.ID == "" {
		return nil, fmt.Errorf("client: ping request id is required")
	}
	return jsonMarshal(pingEnvelope{Type: "request", ID: request.ID})
}

func UnmarshalPingRequest(data []byte) (PingRequest, error) {
	envelope, err := unmarshalPingEnvelope(data)
	if err != nil {
		return PingRequest{}, err
	}
	if envelope.Type != "request" {
		return PingRequest{}, fmt.Errorf("client: unexpected ping message type %q", envelope.Type)
	}
	return PingRequest{ID: envelope.ID}, nil
}

func MarshalPingResponse(response PingResponse) ([]byte, error) {
	if response.ID == "" {
		return nil, fmt.Errorf("client: ping response id is required")
	}
	return jsonMarshal(pingEnvelope{Type: "response", ID: response.ID})
}

func UnmarshalPingResponse(data []byte) (PingResponse, error) {
	envelope, err := unmarshalPingEnvelope(data)
	if err != nil {
		return PingResponse{}, err
	}
	if envelope.Type != "response" {
		return PingResponse{}, fmt.Errorf("client: unexpected ping message type %q", envelope.Type)
	}
	return PingResponse{ID: envelope.ID}, nil
}

func unmarshalPingEnvelope(data []byte) (pingEnvelope, error) {
	var envelope pingEnvelope
	if err := jsonUnmarshal(data, &envelope); err != nil {
		return pingEnvelope{}, fmt.Errorf("client: unmarshal ping message: %w", err)
	}
	if envelope.ID == "" {
		return pingEnvelope{}, fmt.Errorf("client: ping message id is required")
	}
	return envelope, nil
}

func (e *engine) startPingResponder(bindIP net.IP) error {
	conn, err := listenPingUDP(bindIP)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.pingConn = conn
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.runPingResponder(conn)
	}()
	return nil
}

func listenPingUDP(bindIP net.IP) (*net.UDPConn, error) {
	candidates := []*net.UDPAddr{}
	if ip4 := bindIP.To4(); ip4 != nil {
		candidates = append(candidates, &net.UDPAddr{IP: append(net.IP(nil), ip4...), Port: PingPort})
	}
	candidates = append(candidates, &net.UDPAddr{IP: net.IPv4zero, Port: PingPort})

	var lastErr error
	for _, candidate := range candidates {
		conn, err := net.ListenUDP("udp4", candidate)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("client: listen ping udp on port %d: %w", PingPort, lastErr)
}

func (e *engine) runPingResponder(conn *net.UDPConn) {
	buffer := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if e.runCtx != nil {
					select {
					case <-e.runCtx.Done():
						return
					default:
					}
				}
				continue
			}
			return
		}

		request, err := UnmarshalPingRequest(buffer[:n])
		if err != nil {
			continue
		}

		response, err := MarshalPingResponse(PingResponse{ID: request.ID})
		if err != nil {
			continue
		}
		_, _ = conn.WriteToUDP(response, addr)
	}
}
