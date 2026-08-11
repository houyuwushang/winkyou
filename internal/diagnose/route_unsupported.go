//go:build !linux && !windows

package diagnose

import "context"

func inspectDefaultRoute(context.Context) DefaultRouteStatus {
	return DefaultRouteStatus{State: RouteUnavailable, Detail: "passive default-route inspection is not implemented on this platform"}
}
