//go:build windows && fieldc1c

package netif

import (
	"context"
	"net"
	"sync/atomic"
)

// Only the public authority adapter below can produce a permit in production.
// The private seam permits fake-only tests without adding an Instance issuer.
type fieldWindowsPermit struct {
	binding fieldWindowsBinding
	valid   func() bool
	used    *atomic.Bool
}

type fieldTunDevice interface {
	batchTunDevice
	LUID() uint64
}

type fieldWintunFactory interface {
	preflight() error
	create(fieldWindowsBinding) (fieldTunDevice, error)
}

type FieldInterface struct{}

type FieldInterfaceWitness struct {
	KernelPacketsRead       uint64 `json:"kernel_packets_read"`
	KernelPacketsWritten    uint64 `json:"kernel_packets_written"`
	Closed                  bool   `json:"closed"`
	InterfaceAbsent         bool   `json:"interface_absent"`
	InterfaceChecked        bool   `json:"interface_checked"`
	ReaderFailedBeforeClose bool   `json:"reader_failed_before_close"`
	AddressesAbsent         bool   `json:"addresses_absent"`
	RoutesAbsent            bool   `json:"routes_absent"`
	RollbackConflict        bool   `json:"rollback_conflict"`
}

func PreflightFieldInterface(FieldInterfaceAuthority) error { return ErrFieldInterface }
func NewFieldInterface(context.Context, FieldInterfaceAuthority) (*FieldInterface, error) {
	return nil, ErrFieldInterface
}
func newFieldWindowsInterface(context.Context, fieldWindowsPermit, fieldIPOperations, fieldWintunFactory) (*FieldInterface, error) {
	return nil, ErrFieldInterface
}
func (f *FieldInterface) Name() string                      { return "" }
func (f *FieldInterface) Type() string                      { return "tun" }
func (f *FieldInterface) MTU() int                          { return 0 }
func (f *FieldInterface) SetIP(net.IP, net.IPMask) error    { return ErrFieldInterface }
func (f *FieldInterface) AddRoute(*net.IPNet, net.IP) error { return ErrFieldInterface }
func (f *FieldInterface) RemoveRoute(*net.IPNet) error      { return ErrFieldInterface }
func (f *FieldInterface) ValidTransport() bool              { return false }
func (f *FieldInterface) Read([]byte) (int, error)          { return 0, net.ErrClosed }
func (f *FieldInterface) Write([]byte) (int, error)         { return 0, net.ErrClosed }
func (f *FieldInterface) InjectPacket([]byte) (int, error)  { return 0, ErrFieldInterface }
func (f *FieldInterface) ReceivePacket([]byte) (int, error) { return 0, net.ErrClosed }
func (f *FieldInterface) Close() error                      { return nil }
func (f *FieldInterface) Witness() FieldInterfaceWitness    { return FieldInterfaceWitness{} }
