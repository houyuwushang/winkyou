//go:build linux

package natlab

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// RunInNamespace uses a dedicated goroutine locked to one OS thread, enters
// the named iproute2 network namespace, runs body, and restores the original
// namespace before unlocking the thread. If restoration fails, the locked
// goroutine exits without unlocking so Go discards the contaminated OS thread.
// Sockets opened synchronously in body remain bound to that namespace after
// body starts their worker goroutines. A callback panic or runtime.Goexit is
// converted into an error after the original namespace has been restored.
func RunInNamespace(name string, body func() error) error {
	if !safeNamePattern.MatchString(name) || body == nil {
		return errors.New("natlab: valid namespace name and callback are required")
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := os.Open("/proc/self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("natlab: open original namespace: %w", err)
			return
		}
		target, err := os.Open("/var/run/netns/" + name)
		if err != nil {
			_ = original.Close()
			runtime.UnlockOSThread()
			result <- fmt.Errorf("natlab: open target namespace %q: %w", name, err)
			return
		}
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			_ = target.Close()
			_ = original.Close()
			runtime.UnlockOSThread()
			result <- fmt.Errorf("natlab: enter namespace %q: %w", name, err)
			return
		}

		var bodyErr error
		bodyReturned := false
		restored := false
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					bodyErr = fmt.Errorf("natlab: namespace callback panicked: %v", recovered)
				}
				if !bodyReturned && bodyErr == nil {
					bodyErr = errors.New("natlab: namespace callback terminated its goroutine")
				}
				restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET)
				_ = target.Close()
				_ = original.Close()
				if restoreErr == nil {
					runtime.UnlockOSThread()
					restored = true
				}
				var restoreWrapped error
				if restoreErr != nil {
					restoreWrapped = fmt.Errorf("natlab: restore original namespace: %w", restoreErr)
				}
				result <- errors.Join(bodyErr, restoreWrapped)
			}()
			bodyErr = body()
			bodyReturned = true
		}()
		if !restored {
			// A goroutine that exits while locked causes the runtime to discard
			// its OS thread instead of returning a wrong-namespace thread to the
			// scheduler.
			runtime.Goexit()
		}
	}()
	return <-result
}
