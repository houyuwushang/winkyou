//go:build linux && fieldc1c

package netif

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// This is a bounded local-kernel control fd, not an IP socket or a child.
// Do not substitute an Internet family, an arbitrary protocol, or exec("ip").
func openFieldKernelControl() (int, error) {
	return unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
}

type fieldKernelControl struct {
	fd       int
	sequence uint32
	end      time.Time
}

// Netlink attribute flag bits 15 (nested) and 14 (network byte order) are not
// part of the ABI type identifier.
const fieldNLATypeMask uint16 = 0x3fff

func (control *fieldKernelControl) rejectAddressConflict(local, peer [4]byte) error {
	control.sequence++
	request := make([]byte, 24)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_GETADDR)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], control.sequence)
	request[16] = unix.AF_INET
	if control.remainingDeadline() != nil || unix.Sendto(control.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return ErrFieldInterface
	}
	var buffer [32768]byte
	for batch := 0; batch < 128; batch++ {
		if control.remainingDeadline() != nil {
			return ErrFieldInterface
		}
		n, from, err := unix.Recvfrom(control.fd, buffer[:], 0)
		if err != nil {
			return ErrFieldInterface
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return ErrFieldInterface
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return ErrFieldInterface
		}
		for _, message := range messages {
			if message.Header.Seq != control.sequence || message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return ErrFieldInterface
			}
			if message.Header.Type == unix.NLMSG_DONE {
				return fieldDumpDone(message.Data)
			}
			if message.Header.Type != unix.RTM_NEWADDR || len(message.Data) < 8 || message.Data[0] != unix.AF_INET {
				return ErrFieldInterface
			}
			attributes, err := syscall.ParseNetlinkRouteAttr(&message)
			if err != nil {
				return ErrFieldInterface
			}
			for _, attribute := range attributes {
				if attribute.Attr.Type != unix.IFA_ADDRESS && attribute.Attr.Type != unix.IFA_LOCAL {
					continue
				}
				if len(attribute.Value) != 4 {
					return ErrFieldInterface
				}
				if bytes.Equal(attribute.Value, local[:]) || bytes.Equal(attribute.Value, peer[:]) {
					return ErrFieldInterface
				}
			}
		}
	}
	return ErrFieldInterface
}

func (control *fieldKernelControl) remainingDeadline() error {
	remaining := time.Until(control.end)
	if remaining <= 0 {
		return ErrFieldInterface
	}
	timeout := unix.NsecToTimeval(remaining.Nanoseconds())
	if unix.SetsockoptTimeval(control.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout) != nil || unix.SetsockoptTimeval(control.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout) != nil {
		return ErrFieldInterface
	}
	return nil
}

// Reject every existing native WireGuard interface conservatively. No key
// query or UAPI connection is needed, and no unrelated owner is modified.
func (control *fieldKernelControl) rejectExistingWireGuard() error {
	remaining := time.Until(control.end)
	if remaining <= 0 {
		return ErrFieldInterface
	}
	timeout := unix.NsecToTimeval(remaining.Nanoseconds())
	if unix.SetsockoptTimeval(control.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout) != nil {
		return ErrFieldInterface
	}
	control.sequence++
	request := make([]byte, 32)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_GETLINK)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], control.sequence)
	if unix.Sendto(control.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return ErrFieldInterface
	}
	var buffer [32768]byte
	for batch := 0; batch < 128 && time.Now().Before(control.end); batch++ {
		if control.remainingDeadline() != nil {
			return ErrFieldInterface
		}
		n, from, err := unix.Recvfrom(control.fd, buffer[:], 0)
		if err != nil {
			return ErrFieldInterface
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return ErrFieldInterface
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return ErrFieldInterface
		}
		for _, message := range messages {
			if message.Header.Seq != control.sequence || message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return ErrFieldInterface
			}
			if message.Header.Type == unix.NLMSG_DONE {
				return fieldDumpDone(message.Data)
			}
			if message.Header.Type != unix.RTM_NEWLINK || len(message.Data) < 16 {
				return ErrFieldInterface
			}
			attrs, err := syscall.ParseNetlinkRouteAttr(&message)
			if err != nil {
				return ErrFieldInterface
			}
			for _, attribute := range attrs {
				if attribute.Attr.Type&fieldNLATypeMask != unix.IFLA_LINKINFO {
					continue
				}
				for data := attribute.Value; len(data) > 0; {
					if len(data) < 4 {
						return ErrFieldInterface
					}
					length := int(binary.NativeEndian.Uint16(data))
					kind := binary.NativeEndian.Uint16(data[2:]) & fieldNLATypeMask
					if length < 4 || length > len(data) {
						return ErrFieldInterface
					}
					if kind == unix.IFLA_INFO_KIND && bytes.Equal(bytes.TrimRight(data[4:length], "\x00"), []byte("wireguard")) {
						return ErrFieldInterface
					}
					next := (length + 3) &^ 3
					if next > len(data) {
						return ErrFieldInterface
					}
					data = data[next:]
				}
			}
		}
	}
	return ErrFieldInterface
}

func newFieldKernelControl() (*fieldKernelControl, error) {
	fd, err := openFieldKernelControl()
	if err != nil {
		return nil, ErrFieldInterface
	}
	control := &fieldKernelControl{fd: fd, end: time.Now().Add(2 * time.Second)}
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		_ = unix.Close(fd)
		return nil, ErrFieldInterface
	}
	return control, nil
}

// A multipart dump can end with an error status. DONE is not by itself a
// successful absence witness; unknown or nonzero payloads fail closed.
func fieldDumpDone(data []byte) error {
	if len(data) == 0 || len(data) == 4 && binary.NativeEndian.Uint32(data) == 0 {
		return nil
	}
	return ErrFieldInterface
}

func (control *fieldKernelControl) close() error { return unix.Close(control.fd) }

func fieldAttribute(kind uint16, data []byte) []byte {
	length := len(data) + 4
	result := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(result, uint16(length))
	binary.NativeEndian.PutUint16(result[2:], kind)
	copy(result[4:], data)
	return result
}

func fieldUint32(value uint32) []byte {
	result := make([]byte, 4)
	binary.NativeEndian.PutUint32(result, value)
	return result
}

func (control *fieldKernelControl) request(kind, flags uint16, payload []byte) error {
	remaining := time.Until(control.end)
	if remaining <= 0 {
		return ErrFieldInterface
	}
	timeout := unix.NsecToTimeval(remaining.Nanoseconds())
	if unix.SetsockoptTimeval(control.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout) != nil ||
		unix.SetsockoptTimeval(control.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout) != nil {
		return ErrFieldInterface
	}
	control.sequence++
	request := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], kind)
	binary.NativeEndian.PutUint16(request[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:], control.sequence)
	copy(request[16:], payload)
	if unix.Sendto(control.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return ErrFieldInterface
	}
	var buffer [8192]byte
	for time.Now().Before(control.end) {
		if control.remainingDeadline() != nil {
			return ErrFieldInterface
		}
		n, from, err := unix.Recvfrom(control.fd, buffer[:], 0)
		if err != nil {
			return ErrFieldInterface
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return ErrFieldInterface
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return ErrFieldInterface
		}
		for _, message := range messages {
			if message.Header.Seq != control.sequence || message.Header.Type != unix.NLMSG_ERROR || len(message.Data) < 4 {
				return ErrFieldInterface
			}
			status := int32(binary.NativeEndian.Uint32(message.Data))
			if status == 0 {
				return nil
			}
			return errors.Join(ErrFieldInterface, syscall.Errno(-status))
		}
	}
	return ErrFieldInterface
}

func (control *fieldKernelControl) configure(index, mtu int, local, peer [4]byte) error {
	link := make([]byte, 16)
	binary.NativeEndian.PutUint32(link[4:], uint32(index))
	binary.NativeEndian.PutUint32(link[8:], unix.IFF_UP)
	binary.NativeEndian.PutUint32(link[12:], unix.IFF_UP)
	link = append(link, fieldAttribute(unix.IFLA_MTU, fieldUint32(uint32(mtu)))...)
	if err := control.request(unix.RTM_NEWLINK, 0, link); err != nil {
		return err
	}
	address := []byte{unix.AF_INET, 32, 0, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(address[4:], uint32(index))
	address = append(address, fieldAttribute(unix.IFA_LOCAL, local[:])...)
	address = append(address, fieldAttribute(unix.IFA_ADDRESS, local[:])...)
	if err := control.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, address); err != nil {
		return err
	}
	route := []byte{unix.AF_INET, 32, 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_STATIC, unix.RT_SCOPE_LINK, unix.RTN_UNICAST, 0, 0, 0, 0}
	route = append(route, fieldAttribute(unix.RTA_DST, peer[:])...)
	route = append(route, fieldAttribute(unix.RTA_OIF, fieldUint32(uint32(index)))...)
	route = append(route, fieldAttribute(unix.RTA_PREFSRC, local[:])...)
	return control.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, route)
}
