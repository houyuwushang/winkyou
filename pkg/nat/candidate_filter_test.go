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

func TestPublicDirectCandidateInterfaceFilterRejectsLikelyVirtualOverlays(t *testing.T) {
	filter := buildCandidateInterfaceFilter(ICEConfig{PublicDirectCandidate: true})
	if filter == nil {
		t.Fatal("filter is nil")
	}
	for _, name := range []string{
		"natpierce",
		"Tailscale",
		"vEthernet (WSL)",
		"Docker Desktop",
		"Wintun Userspace Tunnel",
		"WinkYou",
	} {
		if filter(name) {
			t.Fatalf("%q should be excluded for public direct", name)
		}
	}
	for _, name := range []string{"Ethernet", "Wi-Fi", "wlan0", "en0"} {
		if !filter(name) {
			t.Fatalf("%q should be allowed for public direct", name)
		}
	}
}

func TestPublicDirectCandidateInterfaceFilterKeepsExplicitExcludes(t *testing.T) {
	filter := buildCandidateInterfaceFilter(ICEConfig{
		PublicDirectCandidate:     true,
		CandidateInterfaceInclude: []string{"Ethernet", "natpierce"},
		CandidateInterfaceExclude: []string{"Wi-Fi"},
	})
	if filter == nil {
		t.Fatal("filter is nil")
	}
	if !filter("Ethernet") {
		t.Fatal("Ethernet should pass explicit include")
	}
	if filter("Wi-Fi") {
		t.Fatal("Wi-Fi should fail explicit exclude")
	}
	if filter("natpierce") {
		t.Fatal("natpierce should still be excluded for public direct")
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
