//go:build linux && fieldc1c

package netif

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FieldInterface is a non-persistent, exclusively created OS TUN. Control
// injection is restricted to the two frozen inner-control tuples. Business
// traffic traverses the real kernel fd; it is not consumed by the echo queue.
type FieldInterface struct {
	authority               FieldInterfaceAuthority
	file                    *os.File
	kernel, injected, echo  chan []byte
	done, readerDone        chan struct{}
	closeOnce               sync.Once
	closeErr                error
	kernelRead, kernelWrite atomic.Uint64
	readerFailedBeforeClose atomic.Bool
}

type FieldInterfaceWitness struct {
	KernelPacketsRead       uint64 `json:"kernel_packets_read"`
	KernelPacketsWritten    uint64 `json:"kernel_packets_written"`
	Closed                  bool   `json:"closed"`
	InterfaceAbsent         bool   `json:"interface_absent"`
	InterfaceChecked        bool   `json:"interface_checked"`
	ReaderFailedBeforeClose bool   `json:"reader_failed_before_close"`
}

// PreflightFieldInterface observes existing owners but never changes them.
func PreflightFieldInterface(authority FieldInterfaceAuthority) error {
	if !authority.valid() || os.Geteuid() != 0 {
		return ErrFieldInterface
	}
	var uname unix.Utsname
	if unix.Uname(&uname) != nil {
		return ErrFieldInterface
	}
	release := string(uname.Release[:])
	majorMinor := strings.SplitN(strings.TrimRight(release, "\x00"), ".", 3)
	if len(majorMinor) < 2 {
		return ErrFieldInterface
	}
	major, e1 := strconv.Atoi(majorMinor[0])
	minor, e2 := strconv.Atoi(majorMinor[1])
	if e1 != nil || e2 != nil || major < 5 || (major == 5 && minor < 15) {
		return ErrFieldInterface
	}
	if absent, err := fieldInterfaceAbsent(authority.state.name); err != nil || !absent {
		return ErrFieldInterface
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil || len(data) > 1024*1024 {
		return ErrFieldInterface
	}
	if fieldRouteConflict(data, authority.state.local, authority.state.peer) {
		return ErrFieldInterface
	}
	control, err := newFieldKernelControl()
	if err != nil {
		return ErrFieldInterface
	}
	checkErr := control.rejectExistingWireGuard()
	if checkErr == nil {
		checkErr = control.rejectAddressConflict(authority.state.local.As4(), authority.state.peer.As4())
	}
	return errors.Join(checkErr, control.close())
}

func fieldRouteConflict(data []byte, local, peer netip.Addr) bool {
	if !strings.HasPrefix(string(data), "Iface\t") && !strings.HasPrefix(string(data), "Iface ") {
		return true
	}
	for index, line := range strings.Split(string(data), "\n") {
		if index == 0 || line == "" {
			continue
		}
		columns := strings.Fields(line)
		if len(columns) < 8 {
			return true
		}
		destination, e1 := strconv.ParseUint(columns[1], 16, 32)
		mask, e2 := strconv.ParseUint(columns[7], 16, 32)
		if e1 != nil || e2 != nil {
			return true
		}
		// The underlay default route is not replaced or claimed.
		if mask == 0 {
			continue
		}
		for _, address := range []netip.Addr{local, peer} {
			value := address.As4()
			if uint64(binary.LittleEndian.Uint32(value[:]))&mask == destination&mask {
				return true
			}
		}
	}
	return false
}

func NewFieldInterface(ctx context.Context, authority FieldInterfaceAuthority) (*FieldInterface, error) {
	if ctx == nil || ctx.Err() != nil || PreflightFieldInterface(authority) != nil || !authority.state.used.CompareAndSwap(false, true) {
		return nil, ErrFieldInterface
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrFieldInterface
	}
	var file *os.File
	fail := func() (*FieldInterface, error) {
		if file == nil {
			_ = unix.Close(fd)
		} else {
			_ = file.Close()
		}
		return nil, ErrFieldInterface
	}
	request, err := unix.NewIfreq(authority.state.name)
	if err != nil {
		return fail()
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(request))); errno != 0 {
		return fail()
	}
	if request.Name() != authority.state.name {
		return fail()
	}
	if unix.SetNonblock(fd, true) != nil {
		return fail()
	}
	// TUN must be configured before os.NewFile registers it with netpoll.
	// An unattached TUN can latch a poll error and kill the first reader.
	// From this point only os.File owns close, including every failure path.
	file = os.NewFile(uintptr(fd), "owned-field-tun")
	indexBytes, err := os.ReadFile("/sys/class/net/" + authority.state.name + "/ifindex")
	if err != nil || len(indexBytes) > 16 {
		return fail()
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(indexBytes)))
	if err != nil || index <= 0 {
		return fail()
	}
	control, err := newFieldKernelControl()
	if err != nil {
		return fail()
	}
	configureErr := control.configure(index, authority.state.mtu, authority.state.local.As4(), authority.state.peer.As4())
	closeErr := control.close()
	if configureErr != nil || closeErr != nil || ctx.Err() != nil {
		return fail()
	}
	result := &FieldInterface{authority: authority, file: file, kernel: make(chan []byte, 64), injected: make(chan []byte, 8),
		echo: make(chan []byte, 8), done: make(chan struct{}), readerDone: make(chan struct{})}
	go result.readKernel()
	// The orchestrator owns cancellation/drain and may send its already
	// reserved authenticated CLOSE. Do not race it with an independent closer.
	return result, nil
}

func (f *FieldInterface) Name() string                      { return f.authority.state.name }
func (f *FieldInterface) Type() string                      { return "tun" }
func (f *FieldInterface) MTU() int                          { return f.authority.state.mtu }
func (f *FieldInterface) SetIP(net.IP, net.IPMask) error    { return ErrFieldInterface }
func (f *FieldInterface) AddRoute(*net.IPNet, net.IP) error { return ErrFieldInterface }
func (f *FieldInterface) RemoveRoute(*net.IPNet) error      { return ErrFieldInterface }

// ValidTransport checks the concrete owned object, not an embedded interface.
func (f *FieldInterface) ValidTransport() bool {
	if f == nil || !f.authority.valid() || f.file == nil || f.done == nil {
		return false
	}
	select {
	case <-f.done:
		return false
	default:
		return true
	}
}

func (f *FieldInterface) readKernel() {
	defer close(f.readerDone)
	buffer := make([]byte, f.MTU())
	defer clear(buffer)
	for {
		n, err := f.file.Read(buffer)
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
	select {
	case <-f.done:
		return 0, net.ErrClosed
	default:
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
	if len(dst) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(dst, packet), nil
}

func (f *FieldInterface) controlPacket(packet []byte, outbound bool, echoOnly bool) bool {
	if len(packet) < 28 || packet[0] != 0x45 || packet[9] != 17 || binary.BigEndian.Uint16(packet[2:4]) != uint16(len(packet)) {
		return false
	}
	source, destination := f.authority.state.local, f.authority.state.peer
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
	n, err := f.file.Write(packet)
	if err == nil {
		f.kernelWrite.Add(1)
	}
	return n, err
}

func (f *FieldInterface) InjectPacket(packet []byte) (int, error) {
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
	select {
	case packet := <-f.echo:
		defer clear(packet)
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
	if f.file == nil || f.done == nil || f.readerDone == nil {
		return ErrFieldInterface
	}
	f.closeOnce.Do(func() {
		close(f.done)
		f.closeErr = f.file.Close()
		select {
		case <-f.readerDone:
		case <-time.After(2 * time.Second):
			f.closeErr = errors.Join(f.closeErr, ErrFieldInterface)
		}
		for _, queue := range []chan []byte{f.kernel, f.injected, f.echo} {
			drainFieldQueue(queue)
		}
		if absent, err := fieldInterfaceAbsent(f.Name()); err != nil || !absent {
			f.closeErr = errors.Join(f.closeErr, ErrFieldInterface)
		}
	})
	return f.closeErr
}

func drainFieldQueue(queue chan []byte) {
	for {
		select {
		case packet := <-queue:
			clear(packet)
		default:
			return
		}
	}
}

func (f *FieldInterface) Witness() FieldInterfaceWitness {
	result := FieldInterfaceWitness{KernelPacketsRead: f.kernelRead.Load(), KernelPacketsWritten: f.kernelWrite.Load(), ReaderFailedBeforeClose: f.readerFailedBeforeClose.Load()}
	select {
	case <-f.done:
		result.Closed = true
	default:
	}
	var err error
	result.InterfaceAbsent, err = fieldInterfaceAbsent(f.Name())
	result.InterfaceChecked = err == nil
	return result
}

func fieldInterfaceAbsent(name string) (bool, error) {
	_, err := os.Lstat("/sys/class/net/" + name)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, ErrFieldInterface
	}
	return false, nil
}
