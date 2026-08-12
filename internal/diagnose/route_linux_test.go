//go:build linux

package diagnose

import (
	"strings"
	"testing"
)

func TestParseLinuxDefaultRouteSelectsLowestMetric(t *testing.T) {
	table := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth1 00000000 0100000A 0003 0 0 200 00000000 0 0 0\n" +
		"eth0 00000000 0101A8C0 0003 0 0 10 00000000 0 0 0\n"
	status := parseLinuxDefaultRoute(strings.NewReader(table))
	if status.State != RoutePresent || status.Interface != "eth0" || status.Family != "ipv4" {
		t.Fatalf("route status = %+v", status)
	}
}

func TestParseLinuxDefaultRouteRejectsDownRoute(t *testing.T) {
	table := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0101A8C0 0000 0 0 10 00000000 0 0 0\n"
	if status := parseLinuxDefaultRoute(strings.NewReader(table)); status.State != RouteAbsent {
		t.Fatalf("route status = %+v", status)
	}
}
