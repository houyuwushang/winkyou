package natlab

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

const c1cMaintainerProofEnv = "WINKYOU_C1C_MAINTAINER_HOST_PROOF"

var c1cCIAttestations = map[string]string{
	"WINKYOU_GATE_B3_DISPOSABLE_RUNNER":  "github-hosted",
	"GITHUB_ACTIONS":                     "true",
	"RUNNER_ENVIRONMENT":                 "github-hosted",
	"WINKYOU_GATE_B3_HOST_CONNTRACK_CAP": "40000",
}

// Plain values only: the decision cannot query the host or create a namespace.
type c1cProofInput struct {
	Env                                    map[string]string
	EUID                                   int
	SelfNet, InitNet, SelfMount, InitMount uint64
	MountInfo, Registry                    string
	Temp                                   c1cProofTempStat
}

type c1cProofTempStat struct {
	Exists, Directory bool
	UID               uint32
	Mode              fs.FileMode
}

func c1cHostProofMode(in c1cProofInput) (string, error) {
	return "", errors.New("c1c_proof_unimplemented")
}

func c1cValidProofInput() c1cProofInput {
	return c1cProofInput{
		Env:  map[string]string{c1cMaintainerProofEnv: "1", "TMPDIR": "/synthetic/private", "WINKYOU_GATE_B3_REQUIRED": "1"},
		EUID: 0, SelfNet: 11, InitNet: 10, SelfMount: 21, InitMount: 20,
		Registry:  "/var/run/netns",
		MountInfo: "31 25 0:23 /synthetic/private /var/run/netns rw - tmpfs tmpfs rw\n",
		Temp:      c1cProofTempStat{Exists: true, Directory: true, UID: 0, Mode: fs.ModeDir | 0o700},
	}
}

func TestC1cHostProofAttestation(t *testing.T) {
	cases := []struct {
		name, mode, class string
		change            func(*c1cProofInput)
	}{
		{"maintainer", "maintainer", "", func(*c1cProofInput) {}},
		{"ci", "ci", "", func(in *c1cProofInput) {
			*in = c1cProofInput{Env: make(map[string]string)}
			for key, value := range c1cCIAttestations {
				in.Env[key] = value
			}
		}},
		{"missing_attestation", "", "c1c_proof_attestation", func(in *c1cProofInput) { in.Env = nil }},
		{"invalid_maintainer", "", "c1c_proof_attestation", func(in *c1cProofInput) { in.Env[c1cMaintainerProofEnv] = "0" }},
		{"empty_maintainer", "", "c1c_proof_attestation", func(in *c1cProofInput) { in.Env[c1cMaintainerProofEnv] = "" }},
		{"not_root", "", "c1c_proof_root", func(in *c1cProofInput) { in.EUID = 1 }},
		{"init_net", "", "c1c_proof_namespace", func(in *c1cProofInput) { in.SelfNet = in.InitNet }},
		{"init_mount", "", "c1c_proof_namespace", func(in *c1cProofInput) { in.SelfMount = in.InitMount }},
		{"zero_net", "", "c1c_proof_namespace", func(in *c1cProofInput) { in.InitNet = 0 }},
		{"zero_mount", "", "c1c_proof_namespace", func(in *c1cProofInput) { in.SelfMount = 0 }},
		{"not_mountpoint", "", "c1c_proof_registry", func(in *c1cProofInput) { in.MountInfo = "31 25 0:23 / /run rw - tmpfs tmpfs rw\n" }},
		{"mount_prefix", "", "c1c_proof_registry", func(in *c1cProofInput) {
			in.MountInfo = strings.ReplaceAll(in.MountInfo, "/var/run/netns", "/var/run/netns-extra")
		}},
		{"malformed_mountinfo", "", "c1c_proof_registry", func(in *c1cProofInput) { in.MountInfo = "/var/run/netns" }},
		{"shared_registry", "", "c1c_proof_registry", func(in *c1cProofInput) { in.MountInfo = strings.ReplaceAll(in.MountInfo, " rw - ", " rw shared:2 - ") }},
		{"slave_registry", "", "c1c_proof_registry", func(in *c1cProofInput) { in.MountInfo = strings.ReplaceAll(in.MountInfo, " rw - ", " rw master:2 - ") }},
		{"resolved_run_alias", "maintainer", "", func(in *c1cProofInput) {
			in.Registry = "/run/netns"
			in.MountInfo = strings.ReplaceAll(in.MountInfo, "/var/run/netns", "/run/netns")
		}},
		{"unresolved_run_alias", "", "c1c_proof_registry", func(in *c1cProofInput) {
			in.MountInfo = strings.ReplaceAll(in.MountInfo, "/var/run/netns", "/run/netns")
		}},
		{"tmp_unset", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { delete(in.Env, "TMPDIR") }},
		{"tmp_relative", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { in.Env["TMPDIR"] = "relative" }},
		{"tmp_missing", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { in.Temp.Exists = false }},
		{"tmp_file", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { in.Temp.Directory = false }},
		{"tmp_owner", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { in.Temp.UID = 1 }},
		{"tmp_mode", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { in.Temp.Mode = fs.ModeDir | 0o750 }},
		{"tmp_symlink", "", "c1c_proof_tmpdir", func(in *c1cProofInput) { in.Temp.Mode = fs.ModeSymlink | 0o700 }},
	}
	for key := range c1cCIAttestations {
		key := key
		for _, value := range []string{"", c1cCIAttestations[key]} {
			value := value
			name := "mixed_" + key
			if value == "" {
				name += "_empty"
			}
			cases = append(cases, struct {
				name, mode, class string
				change            func(*c1cProofInput)
			}{name, "", "c1c_proof_mixed_attestation", func(in *c1cProofInput) { in.Env[key] = value }})
		}
		cases = append(cases, struct {
			name, mode, class string
			change            func(*c1cProofInput)
		}{"ci_missing_" + key, "", "c1c_proof_attestation", func(in *c1cProofInput) {
			in.Env = make(map[string]string)
			for k, v := range c1cCIAttestations {
				in.Env[k] = v
			}
			delete(in.Env, key)
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := c1cValidProofInput()
			tc.change(&in)
			mode, err := c1cHostProofMode(in)
			class := ""
			if err != nil {
				class = err.Error()
			}
			if mode != tc.mode || class != tc.class {
				t.Fatalf("attestation mode=%q class=%q; want mode=%q class=%q", mode, class, tc.mode, tc.class)
			}
		})
	}
}
