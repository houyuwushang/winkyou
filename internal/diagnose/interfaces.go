package diagnose

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

func inspectInterfaces() InterfaceStatus {
	interfaces, err := net.Interfaces()
	if err != nil {
		return InterfaceStatus{State: InterfacesUnavailable, Detail: boundedText(err.Error(), 512)}
	}
	status := InterfaceStatus{State: InterfacesReady, Count: len(interfaces)}
	details := make([]string, 0)
	for _, networkInterface := range interfaces {
		summary := InterfaceSummary{
			Name:                 networkInterface.Name,
			Index:                networkInterface.Index,
			MTU:                  networkInterface.MTU,
			Up:                   networkInterface.Flags&net.FlagUp != 0,
			Loopback:             networkInterface.Flags&net.FlagLoopback != 0,
			AddressesAreRedacted: true,
		}
		if summary.Up {
			status.UpCount++
		}
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			status.State = InterfacesPartial
			details = append(details, fmt.Sprintf("%s: %v", networkInterface.Name, addressErr))
		} else {
			summary.AddressClasses = addressClasses(addresses)
		}
		status.Interfaces = append(status.Interfaces, summary)
	}
	sort.Slice(status.Interfaces, func(left, right int) bool {
		if status.Interfaces[left].Index == status.Interfaces[right].Index {
			return status.Interfaces[left].Name < status.Interfaces[right].Name
		}
		return status.Interfaces[left].Index < status.Interfaces[right].Index
	})
	if len(details) > 0 {
		status.Detail = boundedText(strings.Join(details, "; "), 512)
	}
	return status
}

func addressClasses(addresses []net.Addr) []string {
	unique := make(map[string]struct{})
	for _, address := range addresses {
		if address == nil {
			continue
		}
		unique[classifyAddress(address.String())] = struct{}{}
	}
	classes := make([]string, 0, len(unique))
	for class := range unique {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	return classes
}

func classifyAddress(value string) string {
	host := strings.TrimSpace(value)
	if slash := strings.LastIndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "unparsed"
	}
	if address.IsLoopback() {
		return familyPrefix(address) + "_loopback"
	}
	if address.IsUnspecified() {
		return familyPrefix(address) + "_unspecified"
	}
	if address.IsLinkLocalUnicast() {
		return familyPrefix(address) + "_link_local"
	}
	if address.IsMulticast() {
		return familyPrefix(address) + "_multicast"
	}
	if address.Is4() {
		shared := netip.MustParsePrefix("100.64.0.0/10")
		if shared.Contains(address) {
			return "ipv4_shared"
		}
		if address.IsPrivate() {
			return "ipv4_private"
		}
		return "ipv4_global"
	}
	if address.IsPrivate() {
		return "ipv6_unique_local"
	}
	return "ipv6_global"
}

func familyPrefix(address netip.Addr) string {
	if address.Is4() {
		return "ipv4"
	}
	return "ipv6"
}
