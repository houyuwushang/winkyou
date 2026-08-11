//go:build linux

package diagnose

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func inspectDefaultRoute(ctx context.Context) DefaultRouteStatus {
	if err := ctx.Err(); err != nil {
		return DefaultRouteStatus{State: RouteUnavailable, Detail: boundedText(err.Error(), 512)}
	}
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return DefaultRouteStatus{State: RouteUnavailable, Source: "/proc/net/route", Detail: boundedText(err.Error(), 512)}
	}
	defer func() { _ = file.Close() }()
	return parseLinuxDefaultRoute(file)
}

func parseLinuxDefaultRoute(reader io.Reader) DefaultRouteStatus {
	status := DefaultRouteStatus{State: RouteAbsent, Family: "ipv4", Source: "/proc/net/route", Detail: "no active IPv4 default route was found"}
	scanner := bufio.NewScanner(reader)
	bestMetric := int64(^uint64(0) >> 1)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		metric, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			metric = bestMetric
		}
		if status.State == RoutePresent && metric >= bestMetric {
			continue
		}
		bestMetric = metric
		status.State = RoutePresent
		status.Interface = fields[0]
		status.Detail = "active IPv4 default route found; gateway address is redacted"
	}
	if err := scanner.Err(); err != nil {
		return DefaultRouteStatus{State: RouteUnavailable, Family: "ipv4", Source: "/proc/net/route", Detail: boundedText(fmt.Sprintf("read route table: %v", err), 512)}
	}
	return status
}
