package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"winkyou/pkg/tunnel"
)

func TestGenkeyTextOutput(t *testing.T) {
	cmd := newGenkeyCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("genkey execute error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Private:") {
		t.Error("output should contain 'Private:'")
	}
	if !strings.Contains(output, "Public:") {
		t.Error("output should contain 'Public:'")
	}

	// Extract the private key and verify it round-trips.
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var privStr, pubStr string
	for _, line := range lines {
		if strings.HasPrefix(line, "Private:") {
			privStr = strings.TrimSpace(strings.TrimPrefix(line, "Private:"))
		}
		if strings.HasPrefix(line, "Public:") {
			pubStr = strings.TrimSpace(strings.TrimPrefix(line, "Public:"))
		}
	}

	if privStr == "" {
		t.Fatal("could not extract private key from output")
	}
	if pubStr == "" {
		t.Fatal("could not extract public key from output")
	}

	priv, err := tunnel.ParsePrivateKey(privStr)
	if err != nil {
		t.Fatalf("ParsePrivateKey(%q) error: %v", privStr, err)
	}

	// Verify public key derivation matches.
	derivedPub := priv.PublicKey()
	if derivedPub.String() != pubStr {
		t.Errorf("derived public key %q != output public key %q", derivedPub.String(), pubStr)
	}
}

func TestGenkeyJSONOutput(t *testing.T) {
	cmd := newGenkeyCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("genkey --json execute error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\nOutput: %s", err, buf.String())
	}

	privStr, ok := result["private_key"]
	if !ok || privStr == "" {
		t.Fatal("JSON missing private_key")
	}
	pubStr, ok := result["public_key"]
	if !ok || pubStr == "" {
		t.Fatal("JSON missing public_key")
	}

	priv, err := tunnel.ParsePrivateKey(privStr)
	if err != nil {
		t.Fatalf("ParsePrivateKey error: %v", err)
	}
	if priv.PublicKey().String() != pubStr {
		t.Error("derived public key does not match JSON public_key")
	}
}

func TestGenkeyUnique(t *testing.T) {
	// Run genkey twice, ensure different keys.
	getKey := func() string {
		cmd := newGenkeyCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{"--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("genkey error: %v", err)
		}
		var result map[string]string
		json.Unmarshal(buf.Bytes(), &result)
		return result["private_key"]
	}

	k1 := getKey()
	k2 := getKey()
	if k1 == k2 {
		t.Error("two genkey invocations produced the same private key")
	}
}
