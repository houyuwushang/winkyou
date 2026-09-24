//go:build windows && fieldc1c

package netif

import (
	"reflect"
	"testing"
	"unsafe"
)

// C ABI goldens: Microsoft netioapi/ws2ipdef declarations, cross-checked with
// wireguard-windows v0.5.3 (28e903804aa1302b791c24093dd7f42f0c7d0952),
// tunnel/winipcfg/types_test.go and types_32.go/types_64.go. Padding is explicit;
// this table is identical on 386, amd64, arm and arm64, with no DLL calls.
func TestFieldWindowsIPHelperABIGolden(t *testing.T) {
	cases := []struct {
		row      any
		size     uintptr
		wantSize uintptr
		offsets  map[string]uintptr
	}{
		{fieldSockaddr{}, unsafe.Sizeof(fieldSockaddr{}), 28, map[string]uintptr{"Family": 0, "Data": 2}},
		{fieldIPPrefix{}, unsafe.Sizeof(fieldIPPrefix{}), 32, map[string]uintptr{"Address": 0, "Bits": 28}},
		{fieldAddressRow{}, unsafe.Sizeof(fieldAddressRow{}), 80, map[string]uintptr{
			"Address": 0, "LUID": 32, "Index": 40, "PrefixOrigin": 44, "SuffixOrigin": 48, "ValidLifetime": 52,
			"PreferredLifetime": 56, "PrefixLength": 60, "SkipAsSource": 61, "DadState": 64, "ScopeID": 68, "CreationTimestamp": 72}},
		{fieldRouteRow{}, unsafe.Sizeof(fieldRouteRow{}), 104, map[string]uintptr{
			"LUID": 0, "Index": 8, "Destination": 12, "NextHop": 44, "SitePrefixLength": 72, "ValidLifetime": 76,
			"PreferredLifetime": 80, "Metric": 84, "Protocol": 88, "Loopback": 92, "AutoconfigureAddress": 93,
			"Publish": 94, "Immortal": 95, "Age": 96, "Origin": 100}},
		{fieldIPInterfaceRow{}, unsafe.Sizeof(fieldIPInterfaceRow{}), 168, map[string]uintptr{
			"Family": 0, "LUID": 8, "Index": 16, "MaxReassemblySize": 20, "InterfaceIdentifier": 24,
			"MinRouterAdvertisementInterval": 32, "MaxRouterAdvertisementInterval": 36, "AdvertisingEnabled": 40,
			"ForwardingEnabled": 41, "WeakHostSend": 42, "WeakHostReceive": 43, "UseAutomaticMetric": 44,
			"UseNeighborUnreachabilityDetection": 45, "ManagedAddressConfigurationSupported": 46,
			"OtherStatefulConfigurationSupported": 47, "AdvertiseDefaultRoute": 48, "RouterDiscoveryBehavior": 52,
			"DadTransmits": 56, "BaseReachableTime": 60, "RetransmitTime": 64, "PathMTUDiscoveryTimeout": 68,
			"LinkLocalAddressBehavior": 72, "LinkLocalAddressTimeout": 76, "ZoneIndices": 80, "SitePrefixLength": 144,
			"Metric": 148, "MTU": 152, "Connected": 156, "SupportsWakeUpPatterns": 157, "SupportsNeighborDiscovery": 158,
			"SupportsRouterDiscovery": 159, "ReachableTime": 160, "TransmitOffload": 164, "ReceiveOffload": 165, "DisableDefaultRoutes": 166}},
		{fieldIfRow{}, unsafe.Sizeof(fieldIfRow{}), 1352, map[string]uintptr{
			"LUID": 0, "Index": 8, "GUID": 12, "Alias": 28, "Description": 542, "PhysicalLength": 1056, "Physical": 1060,
			"PermanentPhysical": 1092, "MTU": 1124, "Type": 1128, "TunnelType": 1132, "MediaType": 1136, "PhysicalMedium": 1140,
			"AccessType": 1144, "DirectionType": 1148, "StatusFlags": 1152, "OperStatus": 1156, "AdminStatus": 1160,
			"MediaConnectState": 1164, "NetworkGUID": 1168, "ConnectionType": 1184, "Counters": 1192}},
		{fieldIfTable{}, unsafe.Sizeof(fieldIfTable{}), 1360, map[string]uintptr{"Count": 0, "Rows": 8}},
		{fieldAddressTable{}, unsafe.Sizeof(fieldAddressTable{}), 88, map[string]uintptr{"Count": 0, "Rows": 8}},
		{fieldRouteTable{}, unsafe.Sizeof(fieldRouteTable{}), 112, map[string]uintptr{"Count": 0, "Rows": 8}},
	}
	for _, tc := range cases {
		typ := reflect.TypeOf(tc.row)
		t.Run(typ.Name(), func(t *testing.T) {
			if tc.size != tc.wantSize {
				t.Fatalf("size=%d want=%d", tc.size, tc.wantSize)
			}
			for index := 0; index < typ.NumField(); index++ {
				field := typ.Field(index)
				if field.Name == "_" {
					continue
				}
				want, ok := tc.offsets[field.Name]
				if !ok || field.Offset != want {
					t.Fatalf("field=%s offset=%d want=%d covered=%v", field.Name, field.Offset, want, ok)
				}
			}
		})
	}
	if unsafe.Offsetof(fieldIfTable{}.Rows) != 8 || unsafe.Offsetof(fieldAddressTable{}.Rows) != 8 || unsafe.Offsetof(fieldRouteTable{}.Rows) != 8 {
		t.Fatal("OS table slice offsets changed")
	}
}
