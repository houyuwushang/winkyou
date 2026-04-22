package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/coordinator/client"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	mu       sync.Mutex
	db       *sql.DB
	network  netip.Prefix
	leaseTTL time.Duration
	now      func() time.Time
}

func NewSQLiteStore(networkCIDR string, leaseTTL time.Duration, now func() time.Time, path string) (*SQLiteStore, error) {
	if strings.TrimSpace(networkCIDR) == "" {
		networkCIDR = DefaultConfig().NetworkCIDR
	}
	if leaseTTL <= 0 {
		leaseTTL = DefaultConfig().LeaseTTL
	}
	if now == nil {
		now = time.Now
	}
	prefix, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("coordinator server: invalid network cidr: %w", err)
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("coordinator server: sqlite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("coordinator server: create sqlite dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("coordinator server: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &SQLiteStore{db: db, network: prefix.Masked(), leaseTTL: leaseTTL, now: now}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) migrate() error {
	stmts := []string{
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS nodes (
			node_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			public_key TEXT NOT NULL UNIQUE,
			metadata_json TEXT NOT NULL,
			virtual_ip TEXT NOT NULL UNIQUE,
			online INTEGER NOT NULL,
			last_seen_unix INTEGER NOT NULL,
			expires_at_unix INTEGER NOT NULL,
			changed_at_unix INTEGER NOT NULL,
			last_sync_unix INTEGER NOT NULL,
			endpoints_json TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS signals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			to_node TEXT NOT NULL,
			from_node TEXT NOT NULL,
			type INTEGER NOT NULL,
			payload BLOB,
			timestamp_unix INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_to_node_id ON signals(to_node, id);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("coordinator server: sqlite migrate: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) Register(req *client.RegisterRequest, expectedAuthKey string) (*Node, error) {
	if req == nil {
		return nil, fmt.Errorf("coordinator server: register request is nil")
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return nil, fmt.Errorf("coordinator server: public_key is required")
	}
	if strings.TrimSpace(expectedAuthKey) != "" && req.AuthKey != expectedAuthKey {
		return nil, ErrUnauthorized
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if err := s.refreshExpiredLocked(now); err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	node, err := s.getNodeByPublicKeyTx(tx, req.PublicKey)
	if err != nil {
		return nil, err
	}
	if node != nil {
		node.Name = req.Name
		node.Metadata = cloneMap(req.Metadata)
		node.LastSeen = now
		node.ExpiresAt = now.Add(s.leaseTTL)
		node.ChangedAt = now
		node.Online = true
		if err := s.upsertNodeTx(tx, node); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return cloneNode(node), nil
	}

	nextID, err := s.nextNodeIDTx(tx)
	if err != nil {
		return nil, err
	}
	virtualIP, err := s.allocateIPTx(tx)
	if err != nil {
		return nil, err
	}
	node = &Node{NodeID: fmt.Sprintf("node-%06d", nextID), Name: req.Name, PublicKey: req.PublicKey, Metadata: cloneMap(req.Metadata), VirtualIP: virtualIP.String(), Online: true, LastSeen: now, ExpiresAt: now.Add(s.leaseTTL), ChangedAt: now}
	if err := s.upsertNodeTx(tx, node); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return cloneNode(node), nil
}

func (s *SQLiteStore) Heartbeat(nodeID string, timestamp time.Time) (*Node, []string, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, nil, fmt.Errorf("coordinator server: node_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if err := s.refreshExpiredLocked(now); err != nil {
		return nil, nil, err
	}
	node, err := s.getNodeByID(nodeID)
	if err != nil {
		return nil, nil, err
	}
	cutoff := node.LastSync
	if timestamp.IsZero() {
		timestamp = now
	}
	node.LastSeen = timestamp
	node.ExpiresAt = now.Add(s.leaseTTL)
	node.ChangedAt = now
	node.LastSync = now
	node.Online = true
	if err := s.upsertNode(node); err != nil {
		return nil, nil, err
	}

	rows, err := s.db.Query(`SELECT node_id FROM nodes WHERE node_id <> ? AND changed_at_unix > ? ORDER BY node_id`, nodeID, cutoff.Unix())
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var updated []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, nil, err
		}
		updated = append(updated, id)
	}
	return cloneNode(node), updated, nil
}

func (s *SQLiteStore) List(onlineOnly bool) []client.PeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	_ = s.refreshExpiredLocked(now)

	query := `SELECT node_id,name,public_key,metadata_json,virtual_ip,online,last_seen_unix,expires_at_unix,changed_at_unix,last_sync_unix,endpoints_json FROM nodes`
	if onlineOnly {
		query += ` WHERE online = 1`
	}
	query += ` ORDER BY node_id`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var peers []client.PeerInfo
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			continue
		}
		peers = append(peers, toPeerInfo(node))
	}
	return peers
}

func (s *SQLiteStore) Get(nodeID string) (*client.PeerInfo, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, fmt.Errorf("coordinator server: node_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if err := s.refreshExpiredLocked(now); err != nil {
		return nil, err
	}
	node, err := s.getNodeByID(nodeID)
	if err != nil {
		return nil, err
	}
	info := toPeerInfo(node)
	return &info, nil
}

func (s *SQLiteStore) ForwardSignal(notification *client.SignalNotification) (bool, error) {
	if notification == nil {
		return false, fmt.Errorf("coordinator server: signal notification is nil")
	}
	if strings.TrimSpace(notification.FromNode) == "" || strings.TrimSpace(notification.ToNode) == "" {
		return false, fmt.Errorf("coordinator server: signal requires from_node and to_node")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if err := s.refreshExpiredLocked(now); err != nil {
		return false, err
	}
	if _, err := s.getNodeByID(notification.FromNode); err != nil {
		return false, err
	}
	target, err := s.getNodeByID(notification.ToNode)
	if err != nil {
		return false, err
	}
	if !target.Online {
		return false, nil
	}
	ts := notification.Timestamp
	if ts == 0 {
		ts = now.Unix()
	}
	_, err = s.db.Exec(`INSERT INTO signals(to_node, from_node, type, payload, timestamp_unix) VALUES (?,?,?,?,?)`, target.NodeID, notification.FromNode, int(notification.Type), cloneSignal(notification).Payload, ts)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) DrainSignals(nodeID string) ([]client.SignalNotification, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, fmt.Errorf("coordinator server: node_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.getNodeByID(nodeID); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, from_node, to_node, type, payload, timestamp_unix FROM signals WHERE to_node = ? ORDER BY id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	var out []client.SignalNotification
	for rows.Next() {
		var id int64
		var from, to string
		var sigType int
		var payload []byte
		var ts int64
		if err := rows.Scan(&id, &from, &to, &sigType, &payload, &ts); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		out = append(out, client.SignalNotification{FromNode: from, ToNode: to, Type: client.SignalType(sigType), Payload: append([]byte(nil), payload...), Timestamp: ts})
	}
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM signals WHERE id = ?`, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteStore) refreshExpiredLocked(now time.Time) error {
	_, err := s.db.Exec(`UPDATE nodes SET online = 0, changed_at_unix = ? WHERE online = 1 AND expires_at_unix > 0 AND expires_at_unix < ?`, now.Unix(), now.Unix())
	return err
}

func (s *SQLiteStore) nextNodeIDTx(tx *sql.Tx) (uint64, error) {
	rows, err := tx.Query(`SELECT node_id FROM nodes`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var maxID uint64
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return 0, err
		}
		parts := strings.Split(nodeID, "-")
		if len(parts) != 2 {
			continue
		}
		n, _ := strconv.ParseUint(parts[1], 10, 64)
		if n > maxID {
			maxID = n
		}
	}
	return maxID + 1, nil
}

func (s *SQLiteStore) allocateIPTx(tx *sql.Tx) (netip.Addr, error) {
	usedRows, err := tx.Query(`SELECT virtual_ip FROM nodes`)
	if err != nil {
		return netip.Addr{}, err
	}
	defer usedRows.Close()
	used := map[string]struct{}{}
	for usedRows.Next() {
		var ip string
		if err := usedRows.Scan(&ip); err != nil {
			return netip.Addr{}, err
		}
		used[ip] = struct{}{}
	}
	addr := s.network.Addr().Next()
	for {
		if !addr.IsValid() || !s.network.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("coordinator server: network %s is exhausted", s.network)
		}
		if _, ok := used[addr.String()]; !ok {
			return addr, nil
		}
		addr = addr.Next()
	}
}

func (s *SQLiteStore) getNodeByPublicKeyTx(tx *sql.Tx, publicKey string) (*Node, error) {
	row := tx.QueryRow(`SELECT node_id,name,public_key,metadata_json,virtual_ip,online,last_seen_unix,expires_at_unix,changed_at_unix,last_sync_unix,endpoints_json FROM nodes WHERE public_key = ?`, publicKey)
	node, err := scanNode(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return node, nil
}

func (s *SQLiteStore) getNodeByID(nodeID string) (*Node, error) {
	row := s.db.QueryRow(`SELECT node_id,name,public_key,metadata_json,virtual_ip,online,last_seen_unix,expires_at_unix,changed_at_unix,last_sync_unix,endpoints_json FROM nodes WHERE node_id = ?`, nodeID)
	node, err := scanNode(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}
	return node, nil
}

func (s *SQLiteStore) upsertNode(node *Node) error {
	_, err := s.db.Exec(`INSERT INTO nodes(node_id,name,public_key,metadata_json,virtual_ip,online,last_seen_unix,expires_at_unix,changed_at_unix,last_sync_unix,endpoints_json)
VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET
name=excluded.name,
public_key=excluded.public_key,
metadata_json=excluded.metadata_json,
virtual_ip=excluded.virtual_ip,
online=excluded.online,
last_seen_unix=excluded.last_seen_unix,
expires_at_unix=excluded.expires_at_unix,
changed_at_unix=excluded.changed_at_unix,
last_sync_unix=excluded.last_sync_unix,
endpoints_json=excluded.endpoints_json`,
		node.NodeID, node.Name, node.PublicKey, mustJSONMap(node.Metadata), node.VirtualIP, boolInt(node.Online), node.LastSeen.Unix(), node.ExpiresAt.Unix(), node.ChangedAt.Unix(), node.LastSync.Unix(), mustJSONSlice(node.Endpoints))
	return err
}

func (s *SQLiteStore) upsertNodeTx(tx *sql.Tx, node *Node) error {
	_, err := tx.Exec(`INSERT INTO nodes(node_id,name,public_key,metadata_json,virtual_ip,online,last_seen_unix,expires_at_unix,changed_at_unix,last_sync_unix,endpoints_json)
VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET
name=excluded.name,
public_key=excluded.public_key,
metadata_json=excluded.metadata_json,
virtual_ip=excluded.virtual_ip,
online=excluded.online,
last_seen_unix=excluded.last_seen_unix,
expires_at_unix=excluded.expires_at_unix,
changed_at_unix=excluded.changed_at_unix,
last_sync_unix=excluded.last_sync_unix,
endpoints_json=excluded.endpoints_json`,
		node.NodeID, node.Name, node.PublicKey, mustJSONMap(node.Metadata), node.VirtualIP, boolInt(node.Online), node.LastSeen.Unix(), node.ExpiresAt.Unix(), node.ChangedAt.Unix(), node.LastSync.Unix(), mustJSONSlice(node.Endpoints))
	return err
}

type scanner interface{ Scan(dest ...any) error }

func scanNode(s scanner) (*Node, error) {
	var node Node
	var metadataJSON, endpointsJSON string
	var online int
	var lastSeen, expiresAt, changedAt, lastSync int64
	if err := s.Scan(&node.NodeID, &node.Name, &node.PublicKey, &metadataJSON, &node.VirtualIP, &online, &lastSeen, &expiresAt, &changedAt, &lastSync, &endpointsJSON); err != nil {
		return nil, err
	}
	node.Online = online == 1
	node.LastSeen = time.Unix(lastSeen, 0)
	node.ExpiresAt = time.Unix(expiresAt, 0)
	node.ChangedAt = time.Unix(changedAt, 0)
	node.LastSync = time.Unix(lastSync, 0)
	if metadataJSON != "" {
		_ = json.Unmarshal([]byte(metadataJSON), &node.Metadata)
	}
	if endpointsJSON != "" {
		_ = json.Unmarshal([]byte(endpointsJSON), &node.Endpoints)
	}
	return &node, nil
}

func mustJSONMap(v map[string]string) string {
	if len(v) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func mustJSONSlice(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
