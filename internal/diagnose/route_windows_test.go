//go:build windows

package diagnose

import "testing"

func TestParseWindowsDefaultRoute(t *testing.T) {
	status := parseWindowsDefaultRoute([]byte(`{"InterfaceAlias":"Ethernet"}`))
	if status.State != RoutePresent || status.Interface != "Ethernet" || status.Family != "ipv4" {
		t.Fatalf("route status = %+v", status)
	}
	if status := parseWindowsDefaultRoute(nil); status.State != RouteAbsent {
		t.Fatalf("empty route status = %+v", status)
	}
	if status := parseWindowsDefaultRoute([]byte("not-json")); status.State != RouteUnavailable {
		t.Fatalf("invalid route status = %+v", status)
	}
}
