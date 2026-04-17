package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"winkyou/pkg/probe/lab"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fatalf("%v", err)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: netprobe <tcp-serve|tcp-check|udp-serve|udp-check|script-run> [flags]")
	}

	switch args[0] {
	case "tcp-serve":
		return serveTCP(args[1:])
	case "tcp-check":
		return checkTCP(args[1:])
	case "udp-serve":
		return serveUDP(args[1:])
	case "udp-check":
		return checkUDP(args[1:])
	case "script-run":
		return runScript(args[1:], stdout)
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
}

func serveTCP(args []string) error {
	fs := flag.NewFlagSet("tcp-serve", flag.ContinueOnError)
	listenAddr := fs.String("listen", "", "listen address")
	expect := fs.String("expect", "", "expected payload")
	reply := fs.String("reply", "", "reply payload")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	listener, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		return fmt.Errorf("tcp listen: %w", err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(*timeout))

	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("tcp accept: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("tcp read: %w", err)
	}
	if string(buffer[:n]) != *expect {
		return fmt.Errorf("tcp payload = %q, want %q", string(buffer[:n]), *expect)
	}
	if _, err := conn.Write([]byte(*reply)); err != nil {
		return fmt.Errorf("tcp write: %w", err)
	}
	return nil
}

func checkTCP(args []string) error {
	fs := flag.NewFlagSet("tcp-check", flag.ContinueOnError)
	addr := fs.String("addr", "", "remote address")
	message := fs.String("message", "", "request payload")
	expect := fs.String("expect", "", "expected reply")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dialer := net.Dialer{Timeout: *timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp4", *addr)
	if err != nil {
		return fmt.Errorf("tcp dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	if _, err := conn.Write([]byte(*message)); err != nil {
		return fmt.Errorf("tcp write: %w", err)
	}
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("tcp read: %w", err)
	}
	if string(buffer[:n]) != *expect {
		return fmt.Errorf("tcp reply = %q, want %q", string(buffer[:n]), *expect)
	}
	return nil
}

func serveUDP(args []string) error {
	fs := flag.NewFlagSet("udp-serve", flag.ContinueOnError)
	listenAddr := fs.String("listen", "", "listen address")
	expect := fs.String("expect", "", "expected payload")
	reply := fs.String("reply", "", "reply payload")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	addr, err := net.ResolveUDPAddr("udp4", *listenAddr)
	if err != nil {
		return fmt.Errorf("udp resolve listen addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("udp listen: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	buffer := make([]byte, 2048)
	n, remote, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return fmt.Errorf("udp read: %w", err)
	}
	if string(buffer[:n]) != *expect {
		return fmt.Errorf("udp payload = %q, want %q", string(buffer[:n]), *expect)
	}
	if _, err := conn.WriteToUDP([]byte(*reply), remote); err != nil {
		return fmt.Errorf("udp write: %w", err)
	}
	return nil
}

func checkUDP(args []string) error {
	fs := flag.NewFlagSet("udp-check", flag.ContinueOnError)
	addr := fs.String("addr", "", "remote address")
	message := fs.String("message", "", "request payload")
	expect := fs.String("expect", "", "expected reply")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	conn, err := net.DialTimeout("udp4", *addr, *timeout)
	if err != nil {
		return fmt.Errorf("udp dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	if _, err := conn.Write([]byte(*message)); err != nil {
		return fmt.Errorf("udp write: %w", err)
	}
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("udp read: %w", err)
	}
	if string(buffer[:n]) != *expect {
		return fmt.Errorf("udp reply = %q, want %q", string(buffer[:n]), *expect)
	}
	return nil
}

func runScript(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("script-run", flag.ContinueOnError)
	scriptPath := fs.String("script", "", "path to probe script JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scriptPath == "" {
		return fmt.Errorf("script-run: --script is required")
	}

	script, err := lab.LoadScript(*scriptPath)
	if err != nil {
		return err
	}
	result, runErr := (lab.Runner{}).Run(context.Background(), script)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if stdout != nil {
		if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
			return err
		}
	}
	return runErr
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
