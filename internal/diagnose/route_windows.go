//go:build windows

package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

const windowsDefaultRouteScript = "$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 InterfaceAlias; if ($null -ne $route) { $route | ConvertTo-Json -Compress }"

type windowsDefaultRoute struct {
	InterfaceAlias string `json:"InterfaceAlias"`
}

func inspectDefaultRoute(ctx context.Context) DefaultRouteStatus {
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsDefaultRouteScript).CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			detail = "passive route inspection timed out"
		}
		return DefaultRouteStatus{State: RouteUnavailable, Family: "ipv4", Source: "Get-NetRoute", Detail: boundedText(detail, 512)}
	}
	return parseWindowsDefaultRoute(output)
}

func parseWindowsDefaultRoute(output []byte) DefaultRouteStatus {
	status := DefaultRouteStatus{State: RouteAbsent, Family: "ipv4", Source: "Get-NetRoute", Detail: "no active IPv4 default route was found"}
	if strings.TrimSpace(string(output)) == "" {
		return status
	}
	var route windowsDefaultRoute
	if err := json.Unmarshal(output, &route); err != nil {
		return DefaultRouteStatus{State: RouteUnavailable, Family: "ipv4", Source: "Get-NetRoute", Detail: boundedText("decode passive route result: "+err.Error(), 512)}
	}
	if strings.TrimSpace(route.InterfaceAlias) == "" {
		return status
	}
	status.State = RoutePresent
	status.Interface = route.InterfaceAlias
	status.Detail = "active IPv4 default route found; gateway address is redacted"
	return status
}
