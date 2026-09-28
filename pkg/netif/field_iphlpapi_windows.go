//go:build windows && fieldc1c

/* SPDX-License-Identifier: MIT
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package netif

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Reference for every ABI row below: wireguard-windows v0.5.3, commit
// 28e903804aa1302b791c24093dd7f42f0c7d0952, tunnel/winipcfg. Explicit padding
// keeps the Windows C layout on both 32- and 64-bit Go targets. No winipcfg
// dependency, callback, Flush, DNS, shell, or general configuration API exists.

// fieldSockaddr: types.go RawSockaddrInet at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet
type fieldSockaddr struct {
	Family uint16
	Data   [26]byte
}

// fieldIPPrefix: types.go IPAddressPrefix at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
type fieldIPPrefix struct {
	Address fieldSockaddr
	Bits    uint8
	_       [3]byte
}

// fieldAddressRow: types_32.go/types_64.go MibUnicastIPAddressRow at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
type fieldAddressRow struct {
	Address           fieldSockaddr
	_                 [4]byte
	LUID              uint64
	Index             uint32
	PrefixOrigin      uint32
	SuffixOrigin      uint32
	ValidLifetime     uint32
	PreferredLifetime uint32
	PrefixLength      uint8
	SkipAsSource      uint8
	_                 [2]byte
	DadState          uint32
	ScopeID           uint32
	CreationTimestamp int64
}

// fieldRouteRow: types.go MibIPforwardRow2 at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type fieldRouteRow struct {
	LUID                 uint64
	Index                uint32
	Destination          fieldIPPrefix
	NextHop              fieldSockaddr
	SitePrefixLength     uint8
	_                    [3]byte
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

// fieldIPInterfaceRow: types_32.go/types_64.go MibIPInterfaceRow at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
type fieldIPInterfaceRow struct {
	Family                               uint16
	_                                    [6]byte
	LUID                                 uint64
	Index                                uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   uint8
	ForwardingEnabled                    uint8
	WeakHostSend                         uint8
	WeakHostReceive                      uint8
	UseAutomaticMetric                   uint8
	UseNeighborUnreachabilityDetection   uint8
	ManagedAddressConfigurationSupported uint8
	OtherStatefulConfigurationSupported  uint8
	AdvertiseDefaultRoute                uint8
	_                                    [3]byte
	RouterDiscoveryBehavior              uint32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMTUDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	MTU                                  uint32
	Connected                            uint8
	SupportsWakeUpPatterns               uint8
	SupportsNeighborDiscovery            uint8
	SupportsRouterDiscovery              uint8
	ReachableTime                        uint32
	TransmitOffload                      uint8
	ReceiveOffload                       uint8
	DisableDefaultRoutes                 uint8
	_                                    byte
}

// fieldIfRow: types_32.go/types_64.go MibIfRow2 at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
type fieldIfRow struct {
	LUID              uint64
	Index             uint32
	GUID              windows.GUID
	Alias             [257]uint16
	Description       [257]uint16
	PhysicalLength    uint32
	Physical          [32]byte
	PermanentPhysical [32]byte
	MTU               uint32
	Type              uint32
	TunnelType        uint32
	MediaType         uint32
	PhysicalMedium    uint32
	AccessType        uint32
	DirectionType     uint32
	StatusFlags       uint8
	_                 [3]byte
	OperStatus        uint32
	AdminStatus       uint32
	MediaConnectState uint32
	NetworkGUID       windows.GUID
	ConnectionType    uint32
	_                 [4]byte
	// The twenty consecutive ULONG64 counters/speeds are read-only. Preserve
	// their ABI bytes, but never compare counters as ownership evidence.
	Counters [20]uint64
}

// fieldIfTable: types_32.go/types_64.go mibIfTable2 at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_table2
type fieldIfTable struct {
	Count uint32
	_     [4]byte
	Rows  [1]fieldIfRow
}

// fieldAddressTable: types_32.go/types_64.go mibUnicastIPAddressTable at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_table
type fieldAddressTable struct {
	Count uint32
	_     [4]byte
	Rows  [1]fieldAddressRow
}

// fieldRouteTable: types_32.go/types_64.go mibIPforwardTable2 at the reference commit.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_table2
type fieldRouteTable struct {
	Count uint32
	_     [4]byte
	Rows  [1]fieldRouteRow
}

// fieldIPHelper adapts the ten narrow transaction operations; no exported raw
// row API exists. The names below are the complete DLL procedure allowlist.
// Wrapper signatures derive from zwinipcfg_windows.go at the reference commit.
type fieldIPHelper struct{}

var (
	fieldIPDLL             = windows.NewLazySystemDLL("iphlpapi.dll")
	fieldProcIfTable       = fieldIPDLL.NewProc("GetIfTable2Ex")
	fieldProcIfEntry       = fieldIPDLL.NewProc("GetIfEntry2")
	fieldProcLUIDGUID      = fieldIPDLL.NewProc("ConvertInterfaceLuidToGuid")
	fieldProcGUIDLUID      = fieldIPDLL.NewProc("ConvertInterfaceGuidToLuid")
	fieldProcAddressTable  = fieldIPDLL.NewProc("GetUnicastIpAddressTable")
	fieldProcRouteTable    = fieldIPDLL.NewProc("GetIpForwardTable2")
	fieldProcFreeTable     = fieldIPDLL.NewProc("FreeMibTable")
	fieldProcGetInterface  = fieldIPDLL.NewProc("GetIpInterfaceEntry")
	fieldProcSetInterface  = fieldIPDLL.NewProc("SetIpInterfaceEntry")
	fieldProcGetAddress    = fieldIPDLL.NewProc("GetUnicastIpAddressEntry")
	fieldProcCreateAddress = fieldIPDLL.NewProc("CreateUnicastIpAddressEntry")
	fieldProcDeleteAddress = fieldIPDLL.NewProc("DeleteUnicastIpAddressEntry")
	fieldProcGetRoute      = fieldIPDLL.NewProc("GetIpForwardEntry2")
	fieldProcCreateRoute   = fieldIPDLL.NewProc("CreateIpForwardEntry2")
	fieldProcDeleteRoute   = fieldIPDLL.NewProc("DeleteIpForwardEntry2")
)

// fieldIPStatus: zwinipcfg_windows.go error conversion at the reference commit.
func fieldIPStatus(code uintptr) error {
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

// snapshot: winipcfg.go GetIfTable2Ex/GetUnicastIPAddressTable/GetIPForwardTable2
// plus types.go table get/free at the reference commit. Read-only, one call per
// table, no retry. OS buffers are copied before FreeMibTable, never exposed.
func (fieldIPHelper) snapshot() (fieldIPSnapshot, error) {
	var result fieldIPSnapshot
	var adapters *fieldIfTable
	code, _, _ := fieldProcIfTable.Call(1, uintptr(unsafe.Pointer(&adapters))) // MibIfTableRaw (netioapi.h)
	if code != 0 {
		return result, fieldIPStatus(code)
	}
	if adapters == nil {
		return result, ErrFieldInterface
	}
	defer fieldProcFreeTable.Call(uintptr(unsafe.Pointer(adapters)))
	if adapters.Count > 16384 {
		return result, ErrFieldInterface
	}
	for _, row := range unsafe.Slice(&adapters.Rows[0], int(adapters.Count)) {
		result.adapters = append(result.adapters, fieldAdapterIdentity{luid: row.LUID, index: row.Index, guid: row.GUID, name: windows.UTF16ToString(row.Alias[:])})
	}
	var addresses *fieldAddressTable
	code, _, _ = fieldProcAddressTable.Call(windows.AF_INET, uintptr(unsafe.Pointer(&addresses)))
	if code != 0 {
		return fieldIPSnapshot{}, fieldIPStatus(code)
	}
	if addresses == nil {
		return fieldIPSnapshot{}, ErrFieldInterface
	}
	defer fieldProcFreeTable.Call(uintptr(unsafe.Pointer(addresses)))
	if addresses.Count > 16384 {
		return fieldIPSnapshot{}, ErrFieldInterface
	}
	result.addresses = append(result.addresses, unsafe.Slice(&addresses.Rows[0], int(addresses.Count))...)
	var routes *fieldRouteTable
	code, _, _ = fieldProcRouteTable.Call(windows.AF_INET, uintptr(unsafe.Pointer(&routes)))
	if code != 0 {
		return fieldIPSnapshot{}, fieldIPStatus(code)
	}
	if routes == nil {
		return fieldIPSnapshot{}, ErrFieldInterface
	}
	defer fieldProcFreeTable.Call(uintptr(unsafe.Pointer(routes)))
	if routes.Count > 16384 {
		return fieldIPSnapshot{}, ErrFieldInterface
	}
	result.routes = append(result.routes, unsafe.Slice(&routes.Rows[0], int(routes.Count))...)
	return result, nil
}

// identity: luid.go Interface/GUID/LUIDFromGUID at the reference commit.
// Both conversion directions and the returned row must agree with the handle.
func (fieldIPHelper) identity(luid uint64) (fieldAdapterIdentity, error) {
	row := fieldIfRow{LUID: luid}
	code, _, _ := fieldProcIfEntry.Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return fieldAdapterIdentity{}, fieldIPStatus(code)
	}
	var guid windows.GUID
	code, _, _ = fieldProcLUIDGUID.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid)))
	if code != 0 {
		return fieldAdapterIdentity{}, fieldIPStatus(code)
	}
	var actual uint64
	code, _, _ = fieldProcGUIDLUID.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&actual)))
	if code != 0 {
		return fieldAdapterIdentity{}, fieldIPStatus(code)
	}
	if actual != luid || row.LUID != luid || row.GUID != guid || row.Index == 0 {
		return fieldAdapterIdentity{}, ErrFieldInterface
	}
	return fieldAdapterIdentity{luid: luid, index: row.Index, guid: guid, name: windows.UTF16ToString(row.Alias[:])}, nil
}

// getInterface: luid.go IPInterface and zwinipcfg_windows.go getIPInterfaceEntry.
// Source commit 28e903804aa1302b791c24093dd7f42f0c7d0952.
func (fieldIPHelper) getInterface(luid uint64) (fieldIPInterfaceRow, error) {
	row := fieldIPInterfaceRow{Family: windows.AF_INET, LUID: luid}
	code, _, _ := fieldProcGetInterface.Call(uintptr(unsafe.Pointer(&row)))
	return row, fieldIPStatus(code)
}

// setInterface: zwinipcfg_windows.go setIPInterfaceEntry at the reference commit.
func (fieldIPHelper) setInterface(row fieldIPInterfaceRow) error {
	code, _, _ := fieldProcSetInterface.Call(uintptr(unsafe.Pointer(&row)))
	return fieldIPStatus(code)
}

// getAddress: zwinipcfg_windows.go getUnicastIPAddressEntry at the reference commit.
func (fieldIPHelper) getAddress(row fieldAddressRow) (fieldAddressRow, error) {
	code, _, _ := fieldProcGetAddress.Call(uintptr(unsafe.Pointer(&row)))
	return row, fieldIPStatus(code)
}

// createAddress: zwinipcfg_windows.go createUnicastIPAddressEntry at the reference commit.
func (fieldIPHelper) createAddress(row fieldAddressRow) error {
	code, _, _ := fieldProcCreateAddress.Call(uintptr(unsafe.Pointer(&row)))
	return fieldIPStatus(code)
}

// deleteAddress: zwinipcfg_windows.go deleteUnicastIPAddressEntry at the reference commit.
func (fieldIPHelper) deleteAddress(row fieldAddressRow) error {
	code, _, _ := fieldProcDeleteAddress.Call(uintptr(unsafe.Pointer(&row)))
	return fieldIPStatus(code)
}

// getRoute: zwinipcfg_windows.go getIPForwardEntry2 at the reference commit.
func (fieldIPHelper) getRoute(row fieldRouteRow) (fieldRouteRow, error) {
	code, _, _ := fieldProcGetRoute.Call(uintptr(unsafe.Pointer(&row)))
	return row, fieldIPStatus(code)
}

// createRoute: zwinipcfg_windows.go createIPForwardEntry2 at the reference commit.
func (fieldIPHelper) createRoute(row fieldRouteRow) error {
	code, _, _ := fieldProcCreateRoute.Call(uintptr(unsafe.Pointer(&row)))
	return fieldIPStatus(code)
}

// deleteRoute: zwinipcfg_windows.go deleteIPForwardEntry2 at the reference commit.
func (fieldIPHelper) deleteRoute(row fieldRouteRow) error {
	code, _, _ := fieldProcDeleteRoute.Call(uintptr(unsafe.Pointer(&row)))
	return fieldIPStatus(code)
}
