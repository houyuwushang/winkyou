package oobattempt

import (
	"bytes"
	"os"
)

func readGolden(path string) ([]byte, error) { return os.ReadFile(path) }

func normalizeCRLF(payload []byte) []byte {
	return bytes.ReplaceAll(payload, []byte("\r\n"), []byte("\n"))
}
