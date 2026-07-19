package mesh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrDataChannelUnavailable = errors.New("mesh: neighbor has no data channel")

// SendData originates one binary data frame. Unlike control floods, user data
// is never duplicated or sequence-deduplicated by the graph router.
func (r *Router) SendData(ctx context.Context, frame DataFrame) error {
	if r == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	frame = cloneDataFrame(frame)
	if frame.Version == 0 {
		frame.Version = DataFrameVersion
	}
	if strings.TrimSpace(frame.Source) == "" {
		frame.Source = r.nodeID
	}
	if frame.Source != r.nodeID {
		return fmt.Errorf("mesh: local node %q cannot originate data from %q", r.nodeID, frame.Source)
	}
	if frame.HopLimit == 0 {
		frame.HopLimit = 16
	}
	if err := ValidateDataFrame(frame); err != nil {
		return err
	}
	if frame.Destination == r.nodeID {
		return r.deliverData(ctx, "", frame)
	}
	return r.forwardData(ctx, "", frame)
}

func (r *Router) HandleInboundData(ctx context.Context, inboundPeer string, frame DataFrame) error {
	if r == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	inboundPeer = strings.TrimSpace(inboundPeer)
	if !r.hasNeighbor(inboundPeer) {
		return r.dropData(inboundPeer, frame, ErrUnknownNeighbor)
	}
	frame = cloneDataFrame(frame)
	if err := ValidateDataFrame(frame); err != nil {
		return r.dropData(inboundPeer, frame, err)
	}
	if frame.Destination == r.nodeID {
		return r.deliverData(ctx, inboundPeer, frame)
	}
	if frame.HopLimit <= 1 {
		return r.dropData(inboundPeer, frame, ErrHopLimitExceeded)
	}
	frame.HopLimit--
	return r.forwardData(ctx, inboundPeer, frame)
}

func (r *Router) forwardData(ctx context.Context, inboundPeer string, frame DataFrame) error {
	nextHop, dataSession, err := r.lookupData(frame.Destination)
	if err != nil {
		return r.dropData(inboundPeer, frame, err)
	}
	if err := dataSession.SendData(ctx, frame); err != nil {
		return r.dropData(inboundPeer, frame, fmt.Errorf("mesh: send data to next hop %q: %w", nextHop, err))
	}
	r.emitData(DataEvent{
		At:          time.Now().UTC(),
		Kind:        EventForwarded,
		NodeID:      r.nodeID,
		InboundPeer: inboundPeer,
		NextHop:     nextHop,
		Frame:       cloneDataFrame(frame),
	})
	return nil
}

func (r *Router) deliverData(ctx context.Context, inboundPeer string, frame DataFrame) error {
	r.emitData(DataEvent{
		At:          time.Now().UTC(),
		Kind:        EventDelivered,
		NodeID:      r.nodeID,
		InboundPeer: inboundPeer,
		Frame:       cloneDataFrame(frame),
	})
	if r.onData == nil {
		return nil
	}
	return r.onData(ctx, cloneDataFrame(frame))
}

func (r *Router) dropData(inboundPeer string, frame DataFrame, err error) error {
	r.emitData(DataEvent{
		At:          time.Now().UTC(),
		Kind:        EventDropped,
		NodeID:      r.nodeID,
		InboundPeer: inboundPeer,
		Frame:       cloneDataFrame(frame),
		DecisionErr: err,
	})
	return err
}

func (r *Router) emitData(event DataEvent) {
	if r != nil && r.onDataEvent != nil {
		r.onDataEvent(event)
	}
}
