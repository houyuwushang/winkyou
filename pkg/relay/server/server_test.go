package server_test

import (
	"context"
	"testing"
	"time"

	relayclient "winkyou/pkg/relay/client"
	relayserver "winkyou/pkg/relay/server"
)

func TestTURNServerAllocate(t *testing.T) {
	srv, err := relayserver.New(relayserver.Config{ListenAddress: "127.0.0.1:0", Realm: "winkyou", Users: map[string]string{"u": "p"}})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer srv.Close()
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	cli, err := relayclient.New(relayclient.Config{ServerURL: "turn:" + srv.Addr().String(), Username: "u", Password: "p", Realm: "winkyou", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	addr, err := cli.Allocate(context.Background())
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if addr == nil || addr.Port == 0 {
		t.Fatalf("invalid relay addr: %+v", addr)
	}
}
