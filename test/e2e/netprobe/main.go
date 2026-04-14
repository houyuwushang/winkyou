package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: netprobe <tcp-serve|tcp-check|udp-serve|udp-check> [flags]")
	}

	switch os.Args[1] {
	case "tcp-serve":
		serveTCP(os.Args[2:])
	case "tcp-check":
		checkTCP(os.Args[2:])
	case "udp-serve":
		serveUDP(os.Args[2:])
	case "udp-check":
		checkUDP(os.Args[2:])
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}

func serveTCP(args []string) {
	fs := flag.NewFlagSet("tcp-serve", flag.ExitOnError)
	listenAddr := fs.String("listen", "", "listen address")
	expect := fs.String("expect", "", "expected payload")
	reply := fs.String("reply", "", "reply payload")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout")
	_ = fs.Parse(args)

	listener, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		fatalf("tcp listen: %v", err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(*timeout))

	conn, err := listener.Accept()
	if err != nil {
		fatalf("tcp accept: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		fatalf("tcp read: %v", err)
	}
	if string(buffer[:n]) != *expect {
		fatalf("tcp payload = %q, want %q", string(buffer[:n]), *expect)
	}
	if _, err := conn.Write([]byte(*reply)); err != nil {
		fatalf("tcp write: %v", err)
	}
}

func checkTCP(args []string) {
	fs := flag.NewFlagSet("tcp-check", flag.ExitOnError)
	addr := fs.String("addr", "", "remote address")
	message := fs.String("message", "", "request payload")
	expect := fs.String("expect", "", "expected reply")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout")
	_ = fs.Parse(args)

	dialer := net.Dialer{Timeout: *timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp4", *addr)
	if err != nil {
		fatalf("tcp dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	if _, err := conn.Write([]byte(*message)); err != nil {
		fatalf("tcp write: %v", err)
	}
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		fatalf("tcp read: %v", err)
	}
	if string(buffer[:n]) != *expect {
		fatalf("tcp reply = %q, want %q", string(buffer[:n]), *expect)
	}
}

func serveUDP(args []string) {
	fs := flag.NewFlagSet("udp-serve", flag.ExitOnError)
	listenAddr := fs.String("listen", "", "listen address")
	expect := fs.String("expect", "", "expected payload")
	reply := fs.String("reply", "", "reply payload")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout")
	_ = fs.Parse(args)

	addr, err := net.ResolveUDPAddr("udp4", *listenAddr)
	if err != nil {
		fatalf("udp resolve listen addr: %v", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		fatalf("udp listen: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	buffer := make([]byte, 2048)
	n, remote, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fatalf("udp read: %v", err)
	}
	if string(buffer[:n]) != *expect {
		fatalf("udp payload = %q, want %q", string(buffer[:n]), *expect)
	}
	if _, err := conn.WriteToUDP([]byte(*reply), remote); err != nil {
		fatalf("udp write: %v", err)
	}
}

func checkUDP(args []string) {
	fs := flag.NewFlagSet("udp-check", flag.ExitOnError)
	addr := fs.String("addr", "", "remote address")
	message := fs.String("message", "", "request payload")
	expect := fs.String("expect", "", "expected reply")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout")
	_ = fs.Parse(args)

	conn, err := net.DialTimeout("udp4", *addr, *timeout)
	if err != nil {
		fatalf("udp dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	if _, err := conn.Write([]byte(*message)); err != nil {
		fatalf("udp write: %v", err)
	}
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		fatalf("udp read: %v", err)
	}
	if string(buffer[:n]) != *expect {
		fatalf("udp reply = %q, want %q", string(buffer[:n]), *expect)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
