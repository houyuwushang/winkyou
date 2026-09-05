package gatecorchestrator

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/pkg/netif"
)

type receivedInnerPacket struct {
	payload []byte
	err     error
}

func postOOBEcho(ctx context.Context, role directattempt.Role, networkInterface netif.MemoryTestInterface,
	binding echoBinding, random io.Reader) (EchoWitness, error) {
	if ctx == nil || networkInterface == nil || random == nil || !role.Valid() || binding.Role != role {
		return EchoWitness{}, ErrEchoInvalid
	}
	echoCtx, cancel := context.WithTimeout(ctx, PostOOBEchoTimeout)
	defer cancel()
	var witness EchoWitness
	if role == directattempt.RoleInitiator {
		var nonce [8]byte
		if _, err := io.ReadFull(random, nonce[:]); err != nil {
			return witness, ErrEchoInvalid
		}
		request, err := buildEchoPacket(binding, echoRequest, nonce)
		if err != nil {
			return witness, err
		}
		if _, err := networkInterface.InjectPacket(request); err != nil {
			clear(request)
			return witness, ErrEchoInvalid
		}
		clear(request)
		witness.RequestsWritten++
		response, err := receiveInnerPacket(echoCtx, networkInterface)
		if err != nil {
			return witness, errors.Join(ErrEchoInvalid, err)
		}
		defer clear(response)
		if _, err := parseEchoPacket(response, binding, echoResponse, &nonce); err != nil {
			return witness, err
		}
		witness.ResponsesRead++
		return witness, nil
	}

	request, err := receiveInnerPacket(echoCtx, networkInterface)
	if err != nil {
		return witness, errors.Join(ErrEchoInvalid, err)
	}
	defer clear(request)
	message, err := parseEchoPacket(request, binding, echoRequest, nil)
	if err != nil {
		return witness, err
	}
	witness.RequestsRead++
	response, err := buildEchoPacket(binding, echoResponse, message.Nonce)
	if err != nil {
		return witness, err
	}
	if _, err := networkInterface.InjectPacket(response); err != nil {
		clear(response)
		return witness, ErrEchoInvalid
	}
	clear(response)
	witness.ResponsesWritten++
	return witness, nil
}

func foregroundSession(callerCtx, sessionCtx context.Context, role directattempt.Role,
	networkInterface netif.MemoryTestInterface, handoff *gateb.ProductHandoff, binding echoBinding,
	random io.Reader, activityInterval time.Duration) (end string, witness EchoWitness, runErr error) {
	if callerCtx == nil || sessionCtx == nil || networkInterface == nil || handoff == nil || random == nil ||
		!role.Valid() || activityInterval <= 0 {
		return "", EchoWitness{}, ErrPostHandoff
	}
	if role == directattempt.RoleInitiator {
		select {
		case <-callerCtx.Done():
			if sessionCtx.Err() != nil {
				return "absolute_ceiling", EchoWitness{Drained: true}, nil
			}
			var nonce [8]byte
			if _, err := io.ReadFull(random, nonce[:]); err != nil {
				return "", EchoWitness{}, ErrPostHandoff
			}
			packet, err := buildEchoPacket(binding, echoClose, nonce)
			if err != nil {
				return "", EchoWitness{}, err
			}
			before := handoff.Witness().Transport.ActiveWrites
			if _, err := networkInterface.InjectPacket(packet); err != nil {
				clear(packet)
				return "", EchoWitness{}, ErrPostHandoff
			}
			clear(packet)
			if err := awaitActiveWrite(sessionCtx, handoff, before); err != nil {
				return "", EchoWitness{}, err
			}
			return "authenticated_close_sent", EchoWitness{CloseWritten: 1, Drained: true}, nil
		case <-sessionCtx.Done():
			return "absolute_ceiling", EchoWitness{Drained: true}, nil
		}
	}

	packets := make(chan receivedInnerPacket, 1)
	readerStop := make(chan struct{})
	readerDone := make(chan struct{})
	defer func() {
		close(readerStop)
		if err := drainInnerReader(networkInterface, readerDone); err != nil {
			witness.Drained = false
			runErr = errors.Join(runErr, err)
		}
	}()
	go func() {
		defer close(readerDone)
		buffer := make([]byte, 65535)
		for {
			n, err := networkInterface.ReceivePacket(buffer)
			if err != nil {
				select {
				case packets <- receivedInnerPacket{err: err}:
				case <-readerStop:
				}
				return
			}
			payload := append([]byte(nil), buffer[:n]...)
			select {
			case packets <- receivedInnerPacket{payload: payload}:
			case <-readerStop:
				clear(payload)
				return
			}
		}
	}()
	ticker := time.NewTicker(activityInterval)
	defer ticker.Stop()
	inactive := 0
	for {
		select {
		case <-callerCtx.Done():
			return "parent_cancel", EchoWitness{Drained: true}, nil
		case <-sessionCtx.Done():
			return "absolute_ceiling", EchoWitness{Drained: true}, nil
		case <-ticker.C:
			inactive++
			if inactive >= SessionInactiveIntervals {
				return "inactivity_ceiling", EchoWitness{Drained: true}, nil
			}
		case received := <-packets:
			if received.err != nil {
				if errors.Is(received.err, net.ErrClosed) && sessionCtx.Err() != nil {
					return "absolute_ceiling", EchoWitness{Drained: true}, nil
				}
				return "", EchoWitness{}, ErrPostHandoff
			}
			inactive = 0
			_, parseErr := parseEchoPacket(received.payload, binding, echoClose, nil)
			clear(received.payload)
			if parseErr == nil {
				return "authenticated_close", EchoWitness{CloseRead: 1, Drained: true}, nil
			}
		}
	}
}

func receiveInnerPacket(ctx context.Context, networkInterface netif.MemoryTestInterface) ([]byte, error) {
	result := make(chan receivedInnerPacket, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		n, err := networkInterface.ReceivePacket(buffer)
		if err != nil {
			result <- receivedInnerPacket{err: err}
			return
		}
		result <- receivedInnerPacket{payload: append([]byte(nil), buffer[:n]...)}
	}()
	select {
	case <-ctx.Done():
		err := drainInnerReader(networkInterface, done)
		select {
		case abandoned := <-result:
			clear(abandoned.payload)
		default:
		}
		return nil, errors.Join(ctx.Err(), err)
	case received := <-result:
		<-done
		return received.payload, received.err
	}
}

// ReceivePacket has no context argument. Terminal cancellation therefore owns
// Close and must witness the reader exiting, not just abandon its goroutine.
func drainInnerReader(networkInterface netif.MemoryTestInterface, done <-chan struct{}) error {
	if err := networkInterface.Close(); err != nil {
		return ErrSessionDrain
	}
	timer := time.NewTimer(SessionDrainTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return ErrSessionDrain
	}
}

func awaitActiveWrite(ctx context.Context, handoff *gateb.ProductHandoff, before int) error {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if handoff.Witness().Transport.ActiveWrites > before {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return ErrPostHandoff
		case <-ticker.C:
		}
	}
}
