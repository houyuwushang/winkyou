//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/pairgen"
)

type c1cRouterHost struct {
	Host                                                                              gateC1bHostConfig
	Binary, Instance, MachineIDFile, Evidence, Summary, Inspect, Inspection, Teardown string
	Owned                                                                             [2]string
	GuardianCrash                                                                     bool
}

// The harness creates only the three disconnected attachment anchors. The
// actual router image, not a surrogate in this test, owns the NAT domains,
// veths, routes, nft rules and observer sockets.
func c1cRouterAnchors(t *testing.T) *n2dTopology {
	t.Helper()
	suffix := fmt.Sprintf("%08x", n2dTopologySequence.Add(1))
	prefix := "wycrtest" + suffix
	topology := &n2dTopology{clientA: prefix + "a", public: prefix + "t", clientB: prefix + "b"}
	for _, ns := range []string{topology.clientA, topology.public, topology.clientB} {
		if _, e := runCommand("ip", "netns", "add", ns); e != nil {
			t.Fatal("router anchor creation failed")
		}
		namespace := ns
		t.Cleanup(func() {
			if b, e := runCommand("ip", "netns", "pids", namespace); e != nil || strings.TrimSpace(string(b)) != "" {
				t.Error("router anchor process residue")
			}
			if _, e := runCommand("ip", "netns", "del", namespace); e != nil {
				t.Error("router anchor removal failed")
			}
		})
	}
	return topology
}
func c1cRouterObserverTopology() hardnatobserve.Topology {
	return hardnatobserve.Topology{Primary: netip.MustParseAddrPort("198.51.100.2:3478"), Other: netip.MustParseAddrPort("203.0.113.1:3479")}
}

func c1cRouterFixture(t *testing.T, topology *n2dTopology, configs [2]fieldC1cHostConfig, binary string) c1cRouterHost {
	return c1cRouterFixtureMode(t, topology, configs, binary, false)
}

func c1cRouterFixtureMode(t *testing.T, topology *n2dTopology, configs [2]fieldC1cHostConfig, binary string, guardianCrash bool) c1cRouterHost {
	t.Helper()
	build, e := buildinfo.ReadFile(binary)
	if e != nil {
		t.Fatal("router exact build metadata unavailable")
	}
	var dependencies []string
	var revision string
	for _, setting := range build.Settings {
		if setting.Key == "vcs.modified" && setting.Value != "false" {
			t.Fatal("router dirty build rejected")
		}
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
	}
	for _, dep := range build.Deps {
		if dep.Replace != nil {
			t.Fatal("router replacement dependency rejected")
		}
		dependencies = append(dependencies, dep.Path+"\x00"+dep.Version+"\x00"+dep.Sum)
	}
	sort.Strings(dependencies)
	old := filepath.Join(configs[0].Host.HomeDirectory, ".winkyou-field", "c1c", filepath.Base(configs[0].Instance))
	payload, e := os.ReadFile(old)
	if e != nil {
		t.Fatal("router endpoint fixture missing")
	}
	defer clear(payload)
	var document map[string]any
	if json.Unmarshal(payload, &document) != nil || document["exact_sha"] != revision {
		t.Fatal("router/endpoint exact revision mismatch")
	}
	var devices []fieldc1c.Device
	encoded, _ := json.Marshal(document["devices"])
	if json.Unmarshal(encoded, &devices) != nil || len(devices) != 2 {
		t.Fatal("router device digests missing")
	}
	deps, _ := json.Marshal(struct {
		Domain        string    `json:"domain"`
		Dependencies  []string  `json:"dependencies"`
		Configuration [2]string `json:"configuration"`
	}{"winkyou-c1c-dependencies-config/1", dependencies, [2]string{devices[0].ConfigurationSHA256, devices[1].ConfigurationSHA256}})
	hash := sha256.Sum256(deps)
	cfg := fieldc1c.RouterConfiguration{Schema: fieldc1c.RouterSchema, DependencyAndConfigurationSHA256: hex.EncodeToString(hash[:]), AllowGlobalConntrackCeiling: false, DisposableEnvironmentReference: "synthetic-exclusive-isolated-runner"}
	cfg.AllowGlobalConntrackCeiling = guardianCrash
	scope := sha256.Sum256([]byte("winkyou-c1c-machine-scope/1\n" + strings.Repeat("3", 32) + "\n/var/lib/winkyou-safety-v2"))
	cfg.MachineScopeReference = "machine-scope-sha256/1:" + hex.EncodeToString(scope[:])
	for i, ns := range []string{topology.clientA, topology.public, topology.clientB} {
		var st unix.Stat_t
		if unix.Stat(filepath.Join("/var/run/netns", ns), &st) != nil {
			t.Fatal("router anchor identity unavailable")
		}
		cfg.Anchors = append(cfg.Anchors, fieldc1c.RouterAnchor{Role: []string{"initiator", "transit", "responder"}[i], Name: ns, Inode: st.Ino})
	}
	cfg.Domains = []fieldc1c.RouterDomain{
		{Role: "initiator", Mode: "apdm_sequential/1", EndpointPrefix: "192.0.2.2/30", GatewayPrefix: "192.0.2.1/30", PublicPrefix: "198.51.100.1/29", TransitPrefix: "198.51.100.2/29"},
		{Role: "responder", Mode: "apdm_sequential/1", EndpointPrefix: "192.0.2.6/30", GatewayPrefix: "192.0.2.5/30", PublicPrefix: "203.0.113.2/29", TransitPrefix: "203.0.113.1/29"},
	}
	document["authority_schema_revision"], document["router"], document["router_binary_sha256"] = fieldc1c.SchemaV2, cfg, fieldC1cFileDigest(t, binary)
	updated, e := json.Marshal(document)
	if e != nil {
		t.Fatal("router synthetic document encode failed")
	}
	defer clear(updated)
	for _, side := range configs {
		path := filepath.Join(side.Host.HomeDirectory, ".winkyou-field", "c1c", filepath.Base(side.Instance))
		// Replace only a just-generated private fixture before any invocation.
		if os.Remove(path) != nil || pairgen.WritePrivateFileExclusive(path, updated) != nil {
			t.Fatal("router endpoint fixture revision failed")
		}
	}
	base := t.TempDir()
	if os.Chmod(base, 0o700) != nil {
		t.Fatal("router fixture permissions failed")
	}
	host := configs[0].Host
	host.HostNamespace = topology.public
	host.Namespace = topology.public
	host.HomeDirectory = filepath.Join(base, "private-home")
	host.MachineBase = filepath.Join(base, "machine-base")
	host.RuntimeBase = filepath.Join(base, "runtime")
	host.RequestFile = filepath.Join(base, "request")
	host.ResultFile = filepath.Join(base, "host-result.json")
	host.StopFile = filepath.Join(base, "stop")
	for _, dir := range []string{host.HomeDirectory, host.MachineBase, host.RuntimeBase, filepath.Join(host.RuntimeBase, "netns"), filepath.Join(host.RuntimeBase, "lock"), filepath.Join(host.RuntimeBase, "sshd")} {
		if os.Mkdir(dir, 0o700) != nil {
			t.Fatal("router private host failed")
		}
	}
	instances := filepath.Join(host.HomeDirectory, ".winkyou-field", "c1c")
	if os.MkdirAll(instances, 0o700) != nil {
		t.Fatal("router private instance directory failed")
	}
	if pairgen.WritePrivateFileExclusive(filepath.Join(instances, filepath.Base(configs[0].Instance)), updated) != nil {
		t.Fatal("router instance write failed")
	}
	id := document["instance_id"].(string)
	ownedHash := sha256.Sum256([]byte("winkyou-c1c-router-owned/1\n" + id))
	stem := "wycr" + hex.EncodeToString(ownedHash[:6])
	result := c1cRouterHost{Host: host, Binary: binary, Instance: configs[0].Instance, MachineIDFile: filepath.Join(base, "machine-id"), Evidence: filepath.Join(instances, "evidence", id, "router"), Summary: filepath.Join(base, "router-summary.json"), Inspect: filepath.Join(base, "inspect"), Inspection: filepath.Join(base, "inspection.json"), Teardown: filepath.Join(base, "teardown.json"), Owned: [2]string{stem + "a", stem + "b"}}
	result.GuardianCrash = guardianCrash
	topology.natA, topology.natB = result.Owned[0], result.Owned[1]
	if pairgen.WritePrivateFileExclusive(result.MachineIDFile, []byte(strings.Repeat("3", 32)+"\n")) != nil {
		t.Fatal("router machine witness write failed")
	}
	return result
}
