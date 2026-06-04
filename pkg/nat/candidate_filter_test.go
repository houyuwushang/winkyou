package nat

import (
	"net"
	"testing"
)

func TestCandidateInterfaceFilter(t *testing.T) {
	filter := buildCandidateInterfaceFilter(ICEConfig{
		CandidateInterfaceInclude: []string{"Ethernet", "wlan0"},
		CandidateInterfaceExclude: []string{"tailscale0"},
	})
	if filter == nil {
		t.Fatal("filter is nil")
	}
	if !filter("ethernet") {
		t.Fatal("ethernet should be allowed")
	}
	if filter("tailscale0") {
		t.Fatal("tailscale0 should be excluded")
	}
	if filter("docker0") {
		t.Fatal("docker0 should not pass include list")
	}
}

func TestCandidateIPFilter(t *testing.T) {
	filter, err := buildCandidateIPFilter(ICEConfig{
		CandidateCIDRInclude: []string{"192.168.0.0/16", "203.0.113.0/24"},
		CandidateCIDRExclude: []string{"192.168.99.0/24"},
	})
	if err != nil {
		t.Fatalf("buildCandidateIPFilter() error = %v", err)
	}
	if filter == nil {
		t.Fatal("filter is nil")
	}
	if !filter(net.ParseIP("192.168.1.10")) {
		t.Fatal("192.168.1.10 should be allowed")
	}
	if filter(net.ParseIP("192.168.99.10")) {
		t.Fatal("192.168.99.10 should be excluded")
	}
	if filter(net.ParseIP("100.64.1.10")) {
		t.Fatal("100.64.1.10 should not pass include list")
	}
}

func TestCandidateIPFilterRejectsInvalidCIDR(t *testing.T) {
	_, err := buildCandidateIPFilter(ICEConfig{CandidateCIDRExclude: []string{"not-a-cidr"}})
	if err == nil {
		t.Fatal("buildCandidateIPFilter() should reject invalid CIDR")
	}
}
