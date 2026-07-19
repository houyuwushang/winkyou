package main

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type eventLog struct {
	nodeID string
	mu     sync.Mutex
	enc    *json.Encoder
}

func newEventLog(nodeID string, output io.Writer) *eventLog {
	if output == nil {
		output = io.Discard
	}
	return &eventLog{nodeID: nodeID, enc: json.NewEncoder(output)}
}

func (l *eventLog) write(kind string, fields map[string]any) {
	if l == nil {
		return
	}
	record := make(map[string]any, len(fields)+3)
	record["at"] = time.Now().UTC()
	record["node_id"] = l.nodeID
	record["event"] = kind
	for key, value := range fields {
		record[key] = value
	}
	l.mu.Lock()
	_ = l.enc.Encode(record)
	l.mu.Unlock()
}
