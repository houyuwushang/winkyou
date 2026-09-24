package architecture

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func c1cEvidenceValid(source string) bool {
	for _, literal := range []string{
		`if [ "$#" -ne 0 ]; then`, `exec /usr/bin/python3 -I -B - <<'PY'`,
		`ROOT = "/root/.winkyou-field/"`, `TEXT_LIMIT = 4 * 1024 * 1024`,
		`TEXT_SUFFIXES = (".json", ".jsonl", ".log", ".txt")`,
		`EXCLUDED = ("c1c/material", "bin", "toolchain", "src", "tmp")`,
		`if os.geteuid() != 0:`, `executable("/usr/bin/python3")`,
		`info.st_uid != 0 or info.st_mode & 0o022`,
		`os.lstat(name, dir_fd=parent)`, `os.O_RDONLY | os.O_NOFOLLOW`,
		`os.O_DIRECTORY`, `os.fstat(fd)`, `info.st_nlink != 1`,
		`hashlib.sha256()`, `"class": "symlink_skipped"`,
		`"class": "evidence_read_failed"`,
		`if relative == "c1c" or relative == "log":`,
		`relative == "c1c/evidence" or relative.startswith("c1c/evidence/") or relative.startswith("log/")`,
		`relative.startswith("c1c/") and relative.count("/") == 1 and relative.endswith(".json")`,
	} {
		if !strings.Contains(source, literal) {
			return false
		}
	}
	for _, forbidden := range []string{
		"subprocess", "os.system", "os.environ", "sys.argv", "--evidence", "eval(", "exec(",
		"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "os.write", "os.unlink",
		"os.rename", "os.mkdir", "os.chmod", "os.chown", "readlink", "follow_symlinks=True",
		"shutil", "socket", "urllib", "ctypes", "open(ROOT", "open(relative",
	} {
		if strings.Contains(source, forbidden) {
			return false
		}
	}
	return strings.Count(source, "os.lstat(name, dir_fd=parent)") == 2 &&
		strings.Count(source, "os.O_RDONLY | os.O_NOFOLLOW") == 3
}

func TestC1cReviewEvidenceContractAndMutations(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts/c1c-review-evidence.sh"))
	if err != nil {
		t.Fatal("review evidence reader unavailable")
	}
	source := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !c1cEvidenceValid(source) {
		t.Fatal("review evidence reader exceeded read-only contract")
	}
	for _, line := range strings.Split(source, "\n") {
		if len(sourcePrivacyLine(line)) != 0 {
			t.Fatal("evidence reader source privacy rejected; values withheld")
		}
	}
	for index, mutation := range [][2]string{
		{`if [ "$#" -ne 0 ]; then`, `if false; then`},
		{`ROOT = "/root/.winkyou-field/"`, `ROOT = "/root/"`},
		{`"c1c/material", `, ""},
		{`relative == "c1c" or relative == "log"`, `relative == "c1c" or relative == "log" or relative == "bin"`},
		{`relative.count("/") == 1`, `relative.count("/") >= 1`},
		{`os.lstat(name, dir_fd=parent)`, `os.stat(name, dir_fd=parent)`},
		{`os.O_RDONLY | os.O_NOFOLLOW`, `os.O_RDONLY`},
		{`info.st_nlink != 1`, `False`},
		{`TEXT_LIMIT = 4 * 1024 * 1024`, `TEXT_LIMIT = 8 * 1024 * 1024`},
		{`hashlib.sha256()`, `subprocess.run(["sha256sum"])`},
		{`os.O_RDONLY | os.O_NOFOLLOW`, `os.O_RDWR | os.O_NOFOLLOW`},
		{`info.st_uid != 0 or info.st_mode & 0o022`, `False`},
	} {
		changed := strings.Replace(source, mutation[0], mutation[1], 1)
		if changed == source || c1cEvidenceValid(changed) {
			t.Fatalf("unsafe evidence reader mutation %d accepted", index)
		}
	}
}

// Execute only extracted definitions against fake commands and an in-memory
// filesystem. Neither privileged script's entry point is run on the test host.
func TestC1cReviewToolsPureSemantics(t *testing.T) {
	root := repositoryRoot(t)
	interpreter := "python3"
	if runtime.GOOS == "windows" {
		interpreter = "python"
	}
	python, err := exec.LookPath(interpreter)
	if err != nil {
		t.Fatal("Python 3 required for review-tool pure contracts")
	}
	for _, mode := range []string{"snapshot", "evidence"} {
		t.Run(mode, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(root, "scripts/c1c-review-"+mode+".sh"))
			if err != nil {
				t.Fatal("review tool unavailable")
			}
			input, err := json.Marshal(map[string]string{"mode": mode, "source": string(b)})
			if err != nil {
				t.Fatal("synthetic input encoding failed")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join(root, "internal/architecture/testdata/c1c_review_tools_test.py"))
			cmd.Stdin = strings.NewReader(string(input))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("pure %s contracts failed: %s", mode, out)
			}
			t.Logf("%s", out)
		})
	}
}
