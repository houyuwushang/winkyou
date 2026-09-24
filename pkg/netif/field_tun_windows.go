//go:build windows && fieldc1c

package netif

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
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

// FieldInterface has no public raw device/LUID/configuration accessor. Kernel
// traffic and the two frozen synthetic control tuples have separate queues.
type FieldInterface struct {
	permit                  fieldWindowsPermit
	device                  fieldTunDevice
	api                     fieldIPOperations
	txn                     *fieldIPTransaction
	before                  fieldIPSnapshot
	kernel, injected, echo  chan []byte
	done, readerDone        chan struct{}
	closeOnce               sync.Once
	closeErr                error
	mu                      sync.Mutex // serializes independent OS observations with rollback
	ioMu                    sync.RWMutex
	kernelRead, kernelWrite atomic.Uint64
	readerFailedBeforeClose atomic.Bool
	rollbackConflict        atomic.Bool
}

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
	UnrelatedUnchanged      bool   `json:"unrelated_unchanged"`
}

func fieldPermit(authority FieldInterfaceAuthority) (fieldWindowsPermit, error) {
	if !authority.valid() || authority.state.used.Load() {
		return fieldWindowsPermit{}, ErrFieldInterface
	}
	state := authority.state
	guid, err := fieldParseGUID(state.wintunGUID)
	if err != nil {
		return fieldWindowsPermit{}, ErrFieldInterface
	}
	permit := fieldWindowsPermit{binding: fieldWindowsBinding{name: state.name, guid: guid, mtu: uint32(state.mtu), local: state.local, peer: state.peer}, valid: authority.valid, used: &state.used}
	if !permit.binding.valid() {
		return fieldWindowsPermit{}, ErrFieldInterface
	}
	return permit, nil
}

// Invalid/expired/used authority is rejected before even read-only OS queries.
func PreflightFieldInterface(authority FieldInterfaceAuthority) error {
	permit, err := fieldPermit(authority)
	if err != nil {
		return ErrFieldInterface
	}
	if (&fieldNativeWintun{}).preflight() != nil {
		return ErrFieldInterface
	}
	snapshot, err := (fieldIPHelper{}).snapshot()
	if err != nil || fieldRejectConflicts(permit.binding, snapshot) != nil || !permit.valid() {
		return ErrFieldInterface
	}
	return nil
}
func NewFieldInterface(ctx context.Context, authority FieldInterfaceAuthority) (*FieldInterface, error) {
	permit, err := fieldPermit(authority)
	if err != nil {
		return nil, ErrFieldInterface
	}
	return newFieldWindowsInterface(ctx, permit, fieldIPHelper{}, &fieldNativeWintun{})
}
func newFieldWindowsInterface(ctx context.Context, permit fieldWindowsPermit, api fieldIPOperations, driver fieldWintunFactory) (*FieldInterface, error) {
	if ctx == nil || ctx.Err() != nil || permit.valid == nil || !permit.valid() || permit.used == nil || permit.used.Load() || !permit.binding.valid() || api == nil || driver == nil {
		return nil, ErrFieldInterface
	}
	if driver.preflight() != nil {
		return nil, ErrFieldInterface
	}
	before, err := api.snapshot()
	if err != nil || fieldRejectConflicts(permit.binding, before) != nil || ctx.Err() != nil || !permit.valid() || !permit.used.CompareAndSwap(false, true) {
		return nil, ErrFieldInterface
	}
	device, err := driver.create(permit.binding)
	if err != nil || device == nil {
		return nil, ErrFieldInterface
	}
	failed := func() (*FieldInterface, error) {
		_ = device.Close() // only this returned, newly created owned handle
		// A Close return is never used as proof of absence.
		_, _ = api.snapshot()
		return nil, ErrFieldInterface
	}
	id, err := api.identity(device.LUID())
	if err != nil || id.luid != device.LUID() || id.guid != permit.binding.guid || id.name != permit.binding.name || ctx.Err() != nil || !permit.valid() {
		return failed()
	}
	txn, err := configureFieldIP(ctx, api, permit.binding, id)
	if err != nil {
		return failed()
	}
	if ctx.Err() != nil || !permit.valid() {
		drain, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = txn.rollback(drain)
		cancel()
		return failed()
	}
	f := &FieldInterface{permit: permit, device: device, api: api, txn: txn, before: before,
		kernel: make(chan []byte, 64), injected: make(chan []byte, 8), echo: make(chan []byte, 8), done: make(chan struct{}), readerDone: make(chan struct{})}
	go f.readKernel()
	// Cancellation is owned by the existing orchestrator's authenticated CLOSE
	// and drain ordering. No competing parent-context closer is installed here.
	return f, nil
}
func (f *FieldInterface) Name() string {
	if f == nil {
		return ""
	}
	return f.permit.binding.name
}
func (f *FieldInterface) Type() string { return "tun" }
func (f *FieldInterface) MTU() int {
	if f == nil {
		return 0
	}
	return int(f.permit.binding.mtu)
}
func (f *FieldInterface) SetIP(net.IP, net.IPMask) error    { return ErrFieldInterface }
func (f *FieldInterface) AddRoute(*net.IPNet, net.IP) error { return ErrFieldInterface }
func (f *FieldInterface) RemoveRoute(*net.IPNet) error      { return ErrFieldInterface }
func (f *FieldInterface) ValidTransport() bool {
	if f == nil || f.device == nil || f.done == nil || f.permit.valid == nil || !f.permit.valid() {
		return false
	}
	select {
	case <-f.done:
		return false
	default:
		return !f.readerFailedBeforeClose.Load()
	}
}
func (f *FieldInterface) readKernel() {
	defer close(f.readerDone)
	buffer := make([]byte, f.MTU())
	defer clear(buffer)
	for {
		n, err := readPacketFromBatchDevice(f.device, buffer)
		if err != nil {
			select {
			case <-f.done:
			default:
				f.readerFailedBeforeClose.Store(true)
			}
			return
		}
		if n <= 0 {
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		f.kernelRead.Add(1)
		select {
		case f.kernel <- packet:
		case <-f.done:
			clear(packet)
			return
		}
	}
}
func (f *FieldInterface) Read(dst []byte) (int, error) {
	if f == nil {
		return 0, net.ErrClosed
	}
	f.ioMu.RLock()
	defer f.ioMu.RUnlock()
	if !f.ValidTransport() {
		return 0, net.ErrClosed
	}
	var packet []byte
	select {
	case packet = <-f.injected:
	case packet = <-f.kernel:
	case <-f.readerDone:
		return 0, net.ErrClosed
	case <-f.done:
		return 0, net.ErrClosed
	}
	defer clear(packet)
	if !f.ValidTransport() {
		return 0, net.ErrClosed
	}
	if len(dst) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(dst, packet), nil
}
func (f *FieldInterface) controlPacket(packet []byte, outbound, echoOnly bool) bool {
	if len(packet) < 28 || packet[0] != 0x45 || packet[9] != 17 || binary.BigEndian.Uint16(packet[2:4]) != uint16(len(packet)) {
		return false
	}
	source, destination := f.permit.binding.local, f.permit.binding.peer
	if !outbound {
		source, destination = destination, source
	}
	if netip.AddrFrom4([4]byte(packet[12:16])) != source || netip.AddrFrom4([4]byte(packet[16:20])) != destination {
		return false
	}
	port := binary.BigEndian.Uint16(packet[20:22])
	if port != binary.BigEndian.Uint16(packet[22:24]) {
		return false
	}
	return (port == 32112 && len(packet) == 76) || (!echoOnly && port == 32113 && len(packet) == 92)
}
func (f *FieldInterface) Write(packet []byte) (int, error) {
	if f == nil {
		return 0, net.ErrClosed
	}
	f.ioMu.RLock()
	defer f.ioMu.RUnlock()
	if !f.ValidTransport() {
		return 0, net.ErrClosed
	}
	if f.controlPacket(packet, false, true) {
		copyOf := append([]byte(nil), packet...)
		select {
		case f.echo <- copyOf:
			return len(packet), nil
		case <-f.done:
			clear(copyOf)
			return 0, net.ErrClosed
		}
	}
	n, err := writePacketToBatchDevice(f.device, packet)
	if err != nil {
		return n, ErrFieldInterface
	}
	f.kernelWrite.Add(1)
	return n, nil
}
func (f *FieldInterface) InjectPacket(packet []byte) (int, error) {
	if f == nil {
		return 0, ErrFieldInterface
	}
	f.ioMu.RLock()
	defer f.ioMu.RUnlock()
	if !f.ValidTransport() || !f.controlPacket(packet, true, false) {
		return 0, ErrFieldInterface
	}
	copyOf := append([]byte(nil), packet...)
	select {
	case f.injected <- copyOf:
		return len(packet), nil
	case <-f.done:
		clear(copyOf)
		return 0, net.ErrClosed
	}
}
func (f *FieldInterface) ReceivePacket(dst []byte) (int, error) {
	if f == nil {
		return 0, net.ErrClosed
	}
	f.ioMu.RLock()
	defer f.ioMu.RUnlock()
	if !f.ValidTransport() {
		return 0, net.ErrClosed
	}
	select {
	case packet := <-f.echo:
		defer clear(packet)
		if !f.ValidTransport() {
			return 0, net.ErrClosed
		}
		if len(dst) < len(packet) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, packet), nil
	case <-f.done:
		return 0, net.ErrClosed
	}
}
func (f *FieldInterface) Close() error {
	if f == nil {
		return nil
	}
	if f.device == nil || f.done == nil || f.readerDone == nil {
		return ErrFieldInterface
	}
	f.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		close(f.done)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.txn.rollback(ctx) != nil {
			f.rollbackConflict.Store(true)
			f.closeErr = ErrFieldInterface
		}
		if f.device.Close() != nil {
			f.closeErr = ErrFieldInterface
		}
		select {
		case <-f.readerDone:
		case <-ctx.Done():
			f.closeErr = ErrFieldInterface
		}
		// done and device.Close unblock all packet calls before taking the
		// exclusive lock: no sender may enqueue after this final drain.
		f.ioMu.Lock()
		for _, queue := range []chan []byte{f.kernel, f.injected, f.echo} {
			fieldDrainWindowsQueue(queue)
		}
		f.ioMu.Unlock()
		w := f.observe()
		deadline, _ := ctx.Deadline()
		if !w.InterfaceChecked || !w.InterfaceAbsent || !w.AddressesAbsent || !w.RoutesAbsent || !w.UnrelatedUnchanged || ctx.Err() != nil || !time.Now().Before(deadline) {
			f.closeErr = ErrFieldInterface
		}
	})
	return f.closeErr
}

func fieldDrainWindowsQueue(queue chan []byte) {
	for {
		select {
		case packet := <-queue:
			clear(packet)
		default:
			return
		}
	}
}

// observe must hold mu; the snapshot is independent of the handle's Close.
func (f *FieldInterface) observe() FieldInterfaceWitness {
	w := FieldInterfaceWitness{KernelPacketsRead: f.kernelRead.Load(), KernelPacketsWritten: f.kernelWrite.Load(), ReaderFailedBeforeClose: f.readerFailedBeforeClose.Load(), RollbackConflict: f.rollbackConflict.Load()}
	select {
	case <-f.done:
		w.Closed = true
	default:
	}
	snapshot, err := f.api.snapshot()
	if err != nil {
		return w
	}
	w.InterfaceChecked, w.InterfaceAbsent, w.AddressesAbsent, w.RoutesAbsent = true, true, true, true
	w.UnrelatedUnchanged = fieldUnrelatedUnchanged(f.before, snapshot, f.txn.identity.luid)
	for _, id := range snapshot.adapters {
		if id.guid == f.permit.binding.guid || id.name == f.Name() || id.luid == f.txn.identity.luid {
			w.InterfaceAbsent = false
		}
	}
	for _, row := range snapshot.addresses {
		if row.LUID == f.txn.identity.luid {
			w.AddressesAbsent = false
		}
	}
	for _, row := range snapshot.routes {
		if row.LUID == f.txn.identity.luid {
			w.RoutesAbsent = false
		}
	}
	return w
}
func (f *FieldInterface) Witness() FieldInterfaceWitness {
	if f == nil || f.api == nil || f.txn == nil {
		return FieldInterfaceWitness{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.observe()
}

// Native driver loading is kept separate from the injectable transaction. It
// is never entered by the pure/fake proof; real adapter proof is a B2 gate.
type fieldNativeWintun struct{}

// The existing wintun module (0fa3db229ce2) uses disk LoadLibraryEx, not an
// embedded resource. Pin the official 0.14.1 bytes and load an absolute,
// protected adjacent path before the wrapper's basename lookup. Dependencies
// search only System32. No working-directory/PATH or System32 DLL fallback.
func fieldDLLHash(arch string) string {
	switch arch {
	case "amd64":
		return "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
	case "386":
		return "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931"
	case "arm64":
		return "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
	case "arm":
		return "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9"
	default:
		return ""
	}
}

// Only SYSTEM, elevated Administrators and the Windows servicing principal
// may own/change the reviewed installation. No user SID is embedded. The
// service SID is NT SERVICE\TrustedInstaller, not a device/account identity.
func fieldTrustedInstallerPrincipal(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func fieldInstallationACL(sd *windows.SECURITY_DESCRIPTOR, leaf bool) bool {
	if sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !fieldTrustedInstallerPrincipal(owner.String()) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount > 256 {
		return false
	}
	// Ancestors must not permit replacement of this child; unrelated sibling
	// creation is irrelevant. The installation directory and DLL forbid every
	// write permission to untrusted principals, including generic masks.
	const fileDeleteChild = 0x40 // FILE_DELETE_CHILD, winnt.h
	mask := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild | windows.GENERIC_ALL | windows.GENERIC_WRITE)
	if leaf {
		mask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil {
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 20 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || int(ace.Header.AceSize) < 8+sid.Len() {
			return false
		}
		if uint32(ace.Mask)&mask != 0 && !fieldTrustedInstallerPrincipal(sid.String()) {
			return false
		}
	}
	return true
}

type fieldDLLSeal struct {
	path  string
	files []*os.File
}

func (seal *fieldDLLSeal) close() {
	for index := len(seal.files) - 1; index >= 0; index-- {
		_ = seal.files[index].Close()
	}
	seal.files = nil
}
func fieldLocalInstallation(path string) bool {
	if len(path) < 4 || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(filepath.VolumeName(path)) != 2 || path[1] != ':' || path[2] != '\\' || strings.ContainsAny(path[2:], ":/\x00") {
		return false
	}
	for _, part := range strings.Split(path[3:], "\\") {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return true
}
func fieldSealDLL() (*fieldDLLSeal, error) {
	executable, err := os.Executable()
	if err != nil || !fieldLocalInstallation(executable) || fieldDLLHash(runtime.GOARCH) == "" {
		return nil, ErrFieldInterface
	}
	directory := filepath.Dir(executable)
	seal := &fieldDLLSeal{path: filepath.Join(directory, "wintun.dll")}
	failed := func() (*fieldDLLSeal, error) { seal.close(); return nil, ErrFieldInterface }
	// Retained handles prevent rename/replacement between inspection and load.
	var ancestors []string
	for current := directory; ; current = filepath.Dir(current) {
		ancestors = append(ancestors, current)
		if len(ancestors) > 32 {
			return failed()
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	for index := len(ancestors) - 1; index >= -1; index-- {
		path := seal.path
		isDir := index >= 0
		if isDir {
			path = ancestors[index]
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return failed()
		}
		access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
		share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
		flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS)
		if !isDir {
			access |= windows.GENERIC_READ
			share = windows.FILE_SHARE_READ
		}
		handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			return failed()
		}
		file := os.NewFile(uintptr(handle), "sealed-wintun-component")
		seal.files = append(seal.files, file)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != isDir || (!isDir && info.NumberOfLinks != 1) {
			return failed()
		}
		sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || !fieldInstallationACL(sd, index <= 0) {
			return failed()
		}
		if !isDir {
			if info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 2*1024*1024 {
				return failed()
			}
			hash := sha256.New()
			if n, err := io.Copy(hash, io.LimitReader(file, 2*1024*1024+1)); err != nil || n != int64(info.FileSizeLow) || hex.EncodeToString(hash.Sum(nil)) != fieldDLLHash(runtime.GOARCH) {
				return failed()
			}
		}
	}
	return seal, nil
}

func fieldWintunUnloaded() bool {
	name, _ := windows.UTF16PtrFromString("wintun.dll")
	var handle windows.Handle
	err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &handle)
	return err == windows.ERROR_MOD_NOT_FOUND && handle == 0
}

func (*fieldNativeWintun) preflight() error {
	if !windows.GetCurrentProcessToken().IsElevated() || !fieldWintunUnloaded() {
		return ErrFieldInterface
	}
	seal, err := fieldSealDLL()
	if err != nil {
		return ErrFieldInterface
	}
	seal.close()
	return nil
}

// The upstream callback consults log.Default().Writer() on each call. Capture
// before LoadLibraryEx/CreateTUN, including failure/Close callbacks. Memory is
// bounded, private, never exported in witness/error text; no public log sink.
type fieldDriverLog struct {
	mu   sync.Mutex
	data []byte
}

func (record *fieldDriverLog) Write(data []byte) (int, error) {
	record.mu.Lock()
	defer record.mu.Unlock()
	remaining := 64*1024 - len(record.data)
	if remaining > len(data) {
		remaining = len(data)
	}
	record.data = append(record.data, data[:remaining]...)
	return len(data), nil
}

var fieldDriverOwner sync.Mutex

type fieldNativeDevice struct {
	fieldTunDevice
	seal     *fieldDLLSeal
	module   windows.Handle
	previous io.Writer
	record   *fieldDriverLog
	once     sync.Once
	err      error
}

func (device *fieldNativeDevice) Close() error {
	device.once.Do(func() {
		if device.fieldTunDevice.Close() != nil {
			device.err = ErrFieldInterface
		}
		// The upstream lazy DLL retains its own process-lifetime reference.
		// Release only our extra reference, never invalidate its cached module.
		if windows.FreeLibrary(device.module) != nil {
			device.err = ErrFieldInterface
		}
		device.seal.close()
		log.SetOutput(device.previous)
		fieldDriverOwner.Unlock()
	})
	return device.err
}
func (*fieldNativeWintun) create(binding fieldWindowsBinding) (fieldTunDevice, error) {
	if !binding.valid() || !fieldDriverOwner.TryLock() {
		return nil, ErrFieldInterface
	}
	if !windows.GetCurrentProcessToken().IsElevated() || !fieldWintunUnloaded() {
		fieldDriverOwner.Unlock()
		return nil, ErrFieldInterface
	}
	seal, err := fieldSealDLL()
	if err != nil {
		fieldDriverOwner.Unlock()
		return nil, ErrFieldInterface
	}
	previous := log.Writer()
	record := &fieldDriverLog{}
	log.SetOutput(record)
	var module windows.Handle
	failed := func() (fieldTunDevice, error) {
		if module != 0 {
			_ = windows.FreeLibrary(module)
		}
		seal.close()
		log.SetOutput(previous)
		fieldDriverOwner.Unlock()
		return nil, ErrFieldInterface
	}
	module, err = windows.LoadLibraryEx(seal.path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return failed()
	}
	var loaded [32768]uint16
	n, err := windows.GetModuleFileName(module, &loaded[0], uint32(len(loaded)))
	if err != nil || n == 0 || n >= uint32(len(loaded)) || !strings.EqualFold(windows.UTF16ToString(loaded[:n]), seal.path) {
		return failed()
	}
	// One creation only. No OpenAdapter/retry/global GUID override exists.
	device, err := wgtun.CreateTUNWithRequestedGUID(binding.name, &binding.guid, int(binding.mtu))
	if err != nil {
		return failed()
	}
	native, ok := device.(fieldTunDevice)
	if !ok {
		_ = device.Close()
		return failed()
	}
	return &fieldNativeDevice{fieldTunDevice: native, seal: seal, module: module, previous: previous, record: record}, nil
}
