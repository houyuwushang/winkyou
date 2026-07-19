package mesh

import (
	"encoding/binary"
	"fmt"
	"strings"

	"winkyou/pkg/peercontrol"
)

const (
	DataFrameVersion    = 1
	dataFrameHeaderSize = 32
	MaxDataNodeIDLength = 1024
	MaxDataPayloadSize  = 256 << 10
	MaxEncodedDataFrame = dataFrameHeaderSize + 2*MaxDataNodeIDLength + MaxDataPayloadSize
)

var dataFrameMagic = [4]byte{'W', 'K', 'D', '1'}

type DataType uint8

const (
	DataTypePacket DataType = iota + 1
	DataTypeStreamOpen
	DataTypeStreamOpenOK
	DataTypeStreamOpenError
	DataTypeStreamData
	DataTypeStreamFIN
	DataTypeStreamReset
	DataTypeStreamACK
)

// DataFrame is the compact routed-data envelope carried separately from JSON
// peer-control messages. Intermediate nodes inspect only this header.
type DataFrame struct {
	Version     uint8
	Type        DataType
	Flags       uint8
	HopLimit    uint8
	Source      string
	Destination string
	FlowID      uint64
	Sequence    uint64
	Payload     []byte
}

func MarshalDataFrame(frame DataFrame) ([]byte, error) {
	if err := ValidateDataFrame(frame); err != nil {
		return nil, err
	}
	source := []byte(frame.Source)
	destination := []byte(frame.Destination)
	raw := make([]byte, dataFrameHeaderSize+len(source)+len(destination)+len(frame.Payload))
	copy(raw[:4], dataFrameMagic[:])
	raw[4] = frame.Version
	raw[5] = byte(frame.Type)
	raw[6] = frame.Flags
	raw[7] = frame.HopLimit
	binary.BigEndian.PutUint16(raw[8:10], uint16(len(source)))
	binary.BigEndian.PutUint16(raw[10:12], uint16(len(destination)))
	binary.BigEndian.PutUint32(raw[12:16], uint32(len(frame.Payload)))
	binary.BigEndian.PutUint64(raw[16:24], frame.FlowID)
	binary.BigEndian.PutUint64(raw[24:32], frame.Sequence)
	offset := dataFrameHeaderSize
	copy(raw[offset:], source)
	offset += len(source)
	copy(raw[offset:], destination)
	offset += len(destination)
	copy(raw[offset:], frame.Payload)
	return raw, nil
}

func UnmarshalDataFrame(raw []byte) (DataFrame, error) {
	if len(raw) < dataFrameHeaderSize {
		return DataFrame{}, fmt.Errorf("mesh: data frame is too short: %d", len(raw))
	}
	if string(raw[:4]) != string(dataFrameMagic[:]) {
		return DataFrame{}, fmt.Errorf("mesh: invalid data frame magic")
	}
	sourceLength := int(binary.BigEndian.Uint16(raw[8:10]))
	destinationLength := int(binary.BigEndian.Uint16(raw[10:12]))
	payloadLength := int(binary.BigEndian.Uint32(raw[12:16]))
	wantLength := dataFrameHeaderSize + sourceLength + destinationLength + payloadLength
	if wantLength != len(raw) || wantLength > MaxEncodedDataFrame {
		return DataFrame{}, fmt.Errorf("mesh: data frame length %d does not match encoded length %d", len(raw), wantLength)
	}
	offset := dataFrameHeaderSize
	frame := DataFrame{
		Version:     raw[4],
		Type:        DataType(raw[5]),
		Flags:       raw[6],
		HopLimit:    raw[7],
		Source:      string(raw[offset : offset+sourceLength]),
		Destination: string(raw[offset+sourceLength : offset+sourceLength+destinationLength]),
		FlowID:      binary.BigEndian.Uint64(raw[16:24]),
		Sequence:    binary.BigEndian.Uint64(raw[24:32]),
		Payload:     append([]byte(nil), raw[offset+sourceLength+destinationLength:]...),
	}
	if err := ValidateDataFrame(frame); err != nil {
		return DataFrame{}, err
	}
	return frame, nil
}

func ValidateDataFrame(frame DataFrame) error {
	if frame.Version != DataFrameVersion {
		return fmt.Errorf("mesh: unsupported data frame version %d", frame.Version)
	}
	switch frame.Type {
	case DataTypePacket, DataTypeStreamOpen, DataTypeStreamOpenOK, DataTypeStreamOpenError,
		DataTypeStreamData, DataTypeStreamFIN, DataTypeStreamReset, DataTypeStreamACK:
	default:
		return fmt.Errorf("mesh: unsupported data frame type %d", frame.Type)
	}
	if frame.Flags != 0 {
		return fmt.Errorf("mesh: unsupported data frame flags 0x%x", frame.Flags)
	}
	if frame.HopLimit == 0 || frame.HopLimit > peercontrol.MaxHopLimit {
		return fmt.Errorf("mesh: data frame hop limit %d is outside 1..%d", frame.HopLimit, peercontrol.MaxHopLimit)
	}
	if strings.TrimSpace(frame.Source) == "" || len(frame.Source) > MaxDataNodeIDLength {
		return fmt.Errorf("mesh: invalid data frame source")
	}
	if strings.TrimSpace(frame.Destination) == "" || len(frame.Destination) > MaxDataNodeIDLength {
		return fmt.Errorf("mesh: invalid data frame destination")
	}
	if frame.FlowID == 0 {
		return fmt.Errorf("mesh: data frame flow id is required")
	}
	if len(frame.Payload) > MaxDataPayloadSize {
		return fmt.Errorf("mesh: data frame payload %d exceeds maximum %d", len(frame.Payload), MaxDataPayloadSize)
	}
	switch frame.Type {
	case DataTypePacket, DataTypeStreamData:
		if len(frame.Payload) == 0 {
			return fmt.Errorf("mesh: data frame type %d requires payload", frame.Type)
		}
	case DataTypeStreamOpen, DataTypeStreamOpenOK, DataTypeStreamFIN, DataTypeStreamACK:
		if len(frame.Payload) != 0 {
			return fmt.Errorf("mesh: data frame type %d does not accept payload", frame.Type)
		}
	}
	return nil
}

func cloneDataFrame(frame DataFrame) DataFrame {
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame
}
