//go:build linux && fieldc1c

package fieldc1c

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const imageProbeEnv = "WINKYOU_C1C_IMAGE_TEST_MODE"

func TestFieldRunningImageChild(t *testing.T) {
	mode := os.Getenv(imageProbeEnv)
	if mode == "" {
		return
	}
	if mode == "unreadable" {
		if syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "") != nil ||
			syscall.Mount("tmpfs", "/proc", "tmpfs", 0, "mode=0700") != nil {
			t.Fatal("private proc view unavailable")
		}
		if _, err := runningImageHash(); err != ErrInvalid {
			t.Fatal("unreadable kernel image did not fail closed")
		}
		return
	}
	if mode != "replaced" {
		t.Fatal("invalid image probe mode")
	}
	fmt.Println("IMAGE_READY")
	if _, err := bufio.NewReader(os.Stdin).ReadByte(); err != nil {
		t.Fatal("image probe gate failed")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := os.ReadFile(path)
	if err != nil || string(replacement) != "replacement, not the running ELF\n" {
		t.Fatal("original pathname was not replaced")
	}
	hash, err := runningImageHash()
	if err != nil || hash != os.Getenv("WINKYOU_C1C_IMAGE_TEST_SHA256") {
		t.Fatal("image hash did not identify the running ELF")
	}
	fmt.Println("IMAGE_RUNNING_ELF_MATCH")
}

func TestFieldRunningImageReplacedPath(t *testing.T) {
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "image")
	if os.WriteFile(image, raw, 0o700) != nil {
		t.Fatal("image copy failed")
	}
	command := exec.Command(image, "-test.run=^TestFieldRunningImageChild$", "-test.count=1")
	command.Env = append(os.Environ(), imageProbeEnv+"=replaced", fmt.Sprintf("WINKYOU_C1C_IMAGE_TEST_SHA256=%x", sha256.Sum256(raw)))
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		if command.ProcessState == nil {
			command.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	line, err := reader.ReadString('\n')
	if err != nil || line != "IMAGE_READY\n" {
		t.Fatal("image child did not reach its gate")
	}
	if os.Remove(image) != nil || os.WriteFile(image, []byte("replacement, not the running ELF\n"), 0o600) != nil {
		t.Fatal("private pathname replacement failed")
	}
	if _, err := input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	input.Close()
	line, err = reader.ReadString('\n')
	if err != nil || line != "IMAGE_RUNNING_ELF_MATCH\n" || command.Wait() != nil {
		t.Fatal("running image regression failed")
	}
}

func TestFieldRunningImageReadFailure(t *testing.T) {
	if os.Getenv("WINKYOU_C1C_IMAGE_REQUIRED") != "1" {
		t.Skip("requires disposable Linux mount proof job")
	}
	if os.Geteuid() != 0 {
		t.Fatal("required image proof is not root")
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/unshare", "--mount", "--propagation", "private",
		source, "-test.run=^TestFieldRunningImageChild$", "-test.count=1")
	command.Env = append(os.Environ(), imageProbeEnv+"=unreadable")
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "PASS") {
		t.Fatalf("kernel image read failure proof: %v %s", err, output)
	}
}
