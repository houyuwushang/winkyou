//go:build linux && natlab && c1bproof

package natlab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/sshassembly"
	"winkyou/internal/v2/sshchildwrapper"
	"winkyou/pkg/config"
	"winkyou/pkg/tunnel"
)

type gateC1bProfile struct {
	name         string
	profile      hardnatplan.Profile
	resource     hardnatplan.ResourceClass
	plannerRoles [2]hardnatplan.Role
}

var gateC1bProfiles = []gateC1bProfile{
	{"predictive", hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, [2]hardnatplan.Role{hardnatplan.RoleInitiator, hardnatplan.RoleResponder}},
	{"asymmetric", hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, [2]hardnatplan.Role{hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet}},
	{"hard16", hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab, [2]hardnatplan.Role{hardnatplan.RoleInitiator, hardnatplan.RoleResponder}},
}

func TestLinuxGateC1bProductProof(t *testing.T) {
	if os.Getenv("WINKYOU_GATE_C1B_REQUIRED") != "1" {
		t.Skip("Gate C1b requires the explicitly isolated Linux proof job")
	}
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	for _, path := range []string{"/usr/bin/ssh", gateC1bSSHDPath(t), "/usr/libexec"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("required isolated SSH tools or privilege-separation directory are unavailable")
		}
	}
	for _, loopbackSSH := range []bool{true, false} {
		for _, profile := range gateC1bProfiles {
			name := "netns-ssh/" + profile.name
			if loopbackSSH {
				name = "loopback-ssh/" + profile.name
			}
			if !t.Run(name, func(t *testing.T) { testGateC1bProfile(t, profile, loopbackSSH) }) {
				t.FailNow() // A failed credential or sample is never retried.
			}
		}
	}
	for _, fault := range []string{"pre-finish-eof", "parent-cancel", "writer-error", "wireguard-failure", "parent-kill", "child-kill", "consumer-crash"} {
		if !t.Run("fault/"+fault, func(t *testing.T) { testGateC1bFault(t, fault) }) {
			t.FailNow()
		}
	}
}

func gateC1bSSHDPath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("WINKYOU_C1B_SSHD_BINARY")
	if path == "" {
		path = "/usr/sbin/sshd"
	}
	if !filepath.IsAbs(path) {
		t.Fatal("isolated sshd fixture binary must have an absolute path")
	}
	return path
}

func testGateC1bProfile(t *testing.T, profile gateC1bProfile, loopbackSSH bool) {
	armGateB3KernelReleaseMargin(t)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	t.Cleanup(func() { cleanupGateC1bEndpointProcesses(t, topology) })
	observer := startGateB2ObserverSet(t, topology.public)
	left, right := gateC1bRouters(t, topology, profile)
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("Gate C1b packet counter setup failed")
	}
	// One exact TCP underlay route to the responder, never an arbitrary
	// port-forwarding feature. It exists only in this disposable NAT namespace.
	var removeSSHPolicy []func()
	if !loopbackSSH {
		// B2's UDP-model policy rule catches all traffic arriving on lan0.
		// Give only the fixed SSH underlay tuple (and its reply) an earlier
		// main-table rule; UDP still goes exclusively through the NAT model.
		for _, rule := range []struct{ namespace, source, destination, portKind string }{
			{topology.natA, n2dClientAAddress, n2dNATBWAN, "dport"},
			{topology.natB, n2dClientBAddress, n2dNATAWAN, "sport"},
		} {
			args := []string{"rule", "add", "priority", "101", "iif", "lan0", "from", rule.source + "/32", "to", rule.destination + "/32",
				"ipproto", "tcp", rule.portKind, "22", "lookup", "main"}
			if _, err := runNamespaced(rule.namespace, "ip", nil, args...); err != nil {
				t.Fatal("Gate C1b exact SSH policy route failed")
			}
			var once sync.Once
			release := func() {
				once.Do(func() {
					if _, err := runNamespaced(rule.namespace, "ip", nil, "rule", "del", "priority", "101"); err != nil {
						t.Error("Gate C1b SSH policy route cleanup failed")
					}
				})
			}
			removeSSHPolicy = append(removeSSHPolicy, release)
			t.Cleanup(release)
		}
		if _, err := runNamespaced(topology.natB, "iptables", nil, "-t", "nat", "-A", "PREROUTING",
			"-i", "wan0", "-p", "tcp", "-d", n2dNATBWAN, "--dport", "22", "-j", "DNAT", "--to-destination", n2dClientBAddress+":22"); err != nil {
			t.Fatal("Gate C1b exact test SSH underlay setup failed")
		}
	}
	configs := gateC1bFixture(t, topology, observer.topology, profile, loopbackSSH)
	server := startGateC1bHost(t, configs[1])
	server.waitFile(t, configs[1].ReadyFile, 5*time.Second)
	client := startGateC1bHost(t, configs[0])
	client.waitFile(t, configs[0].ResultFile, gateC1bHostLimit)
	var results [2]gateC1bProcessResult
	if !readN1JSON(configs[0].ResultFile, &results[0]) {
		t.Fatal("Gate C1b initiator result unavailable")
	}
	// Never hide an already available client failure behind a secondary wait
	// for a child which SSH may not have started. Only frozen classes/stages
	// and counters are published; no raw SSH error or private fixture content.
	if !results[0].OK {
		got := results[0]
		var peer gateC1bProcessResult
		peerResult := readN1JSON(configs[1].ResultFile, &peer)
		var sshd gateC1bSSHDWitness
		_ = readN1JSON(configs[1].ReadyFile+".counts", &sshd)
		t.Logf("Gate C1b peer diagnostic: result=%t class=%s stage=%s stages=%v sshd=%+v", peerResult, peer.Class, peer.Stage, peer.Stages, sshd)
		t.Fatalf("Gate C1b initiator terminal: class=%s stage=%s burned=%t finish=%t ready=%t stages=%v ssh=%+v",
			got.Class, got.Stage, got.Product.CredentialBurned, got.Product.FinishRecorded, got.Product.DataPlaneReady,
			got.Stages, got.Product.Witness.SSH)
	}
	server.waitFile(t, configs[1].ResultFile, 5*time.Second)
	for index := range results {
		if !readN1JSON(configs[index].ResultFile, &results[index]) {
			t.Fatal("Gate C1b private result unavailable")
		}
		got := results[index]
		if !got.OK || !got.Root || !reflect.DeepEqual(got.Stages, gatecorchestrator.ProductProgressSequence) {
			t.Fatalf("Gate C1b terminal rejected: side=%d class=%s stage=%s burned=%t finish=%t ready=%t stages=%v",
				index, got.Class, got.Stage, got.Product.CredentialBurned, got.Product.FinishRecorded,
				got.Product.DataPlaneReady, got.Stages)
		}
		wg := got.Product.Witness.WireGuard
		if !wg.ConsumerReady || wg.ReadinessReads != 1 || wg.ReadinessWrites != 1 ||
			len(wg.Outbound)+wg.ReadinessWrites+wg.CompletionWrites != 3 || len(wg.Inbound)+wg.ReadinessReads+wg.CompletionReads != 3 ||
			!got.Product.Witness.Handoff.OOBDrained || !got.Product.Witness.Handoff.AttemptReleased ||
			!got.Product.Witness.InterfaceClosed || !got.Product.Witness.TunnelStopped {
			t.Fatal("Gate C1b handoff/challenge/echo witness rejected")
		}
		echo := got.Product.Witness.Echo
		if index == 0 && (echo.RequestsWritten != 1 || echo.ResponsesRead != 1 || echo.CloseWritten != 1) ||
			index == 1 && (echo.RequestsRead != 1 || echo.ResponsesWritten != 1 || echo.CloseRead != 1) {
			t.Fatal("Gate C1b directional echo/CLOSE witness rejected")
		}
		if configs[index].UseTUN && (!got.TUN.Used || !got.TUN.Closed || got.TUN.KernelReads == 0 || got.TUN.KernelWrites == 0 ||
			got.TUN.KernelReads != got.TUN.InnerSends || got.TUN.KernelWrites != got.TUN.InnerReads) {
			t.Fatalf("Gate C1b real kernel TUN echo witness rejected: side=%d tun=%+v echo=%+v", index, got.TUN, echo)
		}
	}
	if !results[0].Product.Witness.SSH.Spawned || !results[0].Product.Witness.SSH.Exited || !results[0].Product.Witness.SSH.Drained || results[0].Product.Witness.SSH.Killed {
		t.Fatal("Gate C1b real SSH child exit witness missing")
	}
	client.wait(t)
	server.stop(t)
	for _, namespace := range []string{topology.clientA, topology.clientB} {
		links, linkErr := runNamespaced(namespace, "ip", nil, "-o", "link", "show")
		routes, routeErr := runNamespaced(namespace, "ip", nil, "-o", "route", "show", "table", "all")
		if linkErr != nil || routeErr != nil || strings.Contains(links, "wink-c1b-proof") || strings.Contains(routes, "wink-c1b-proof") {
			t.Fatal("Gate C1b kernel interface/route residue")
		}
	}
	counts := requireGateB2PacketCounts(t, topology)
	for index, actual := range []uint64{counts.InitiatorTotal, counts.ResponderTotal} {
		got := results[index].Product.Witness
		want := uint64(got.GateB.Emissions.UDPPacketsTotal + got.WireGuard.ReadinessWrites + got.WireGuard.CompletionWrites + len(got.WireGuard.Outbound) + got.WireGuard.ActiveWrites)
		if actual != want {
			t.Fatalf("Gate C1b OS packet accounting mismatch: side=%d actual=%d charged=%d", index, actual, want)
		}
	}
	t.Logf("Gate C1b profile=%s loopback_ssh=%t root=true evidence=%d/%d candidates=%d/%d udp=%d/%d challenge=3/3 post_oob_echo=true",
		profile.name, loopbackSSH, results[0].Product.Witness.GateB.Emissions.EvidencePackets,
		results[1].Product.Witness.GateB.Emissions.EvidencePackets, results[0].Product.Witness.GateB.Emissions.CandidatePackets,
		results[1].Product.Witness.GateB.Emissions.CandidatePackets, counts.InitiatorTotal, counts.ResponderTotal)
	governorDirs := []string{filepath.Join(configs[0].MachineBase, "winkyou-safety-v2"), filepath.Join(configs[1].MachineBase, "winkyou-safety-v2")}
	for _, release := range removeSSHPolicy {
		release()
	}
	if profile.profile == hardnatplan.ProfileHardBirthday {
		assertGateB3NoResidue(t, topology, observer, left, right, false, false, governorDirs...)
	} else {
		assertGateB2NoResidue(t, topology, observer, left, right, governorDirs...)
	}
}

// Failure cleanup is not a successful drain witness. Never delete a namespace
// name while a remote child can still own it invisibly. pidfd pins the exact
// enumerated process; the namespace check excludes every host process.
func cleanupGateC1bEndpointProcesses(t *testing.T, topology *n2dTopology) {
	t.Helper()
	for _, namespace := range []string{topology.clientA, topology.clientB} {
		if !safeNamePattern.MatchString(namespace) {
			t.Error("Gate C1b endpoint cleanup identity rejected")
			continue
		}
		expected, err := os.Stat("/run/netns/" + namespace)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Error("Gate C1b endpoint cleanup identity unavailable")
			continue
		}
		output, err := runCommand("ip", "netns", "pids", namespace)
		if err != nil {
			t.Error("Gate C1b endpoint process enumeration failed")
			continue
		}
		for _, value := range strings.Fields(output) {
			pid, err := strconv.Atoi(value)
			if err != nil || pid <= 1 || pid == os.Getpid() {
				t.Error("Gate C1b endpoint process identity rejected")
				continue
			}
			descriptor, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				continue // Already exited; no numeric-PID fallback.
			}
			current, statErr := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
			if statErr == nil && os.SameFile(current, expected) {
				if !t.Failed() {
					t.Error("Gate C1b unproven endpoint drain required cleanup")
				}
				_ = unix.PidfdSendSignal(descriptor, unix.SIGKILL, nil, 0)
			}
			_ = unix.Close(descriptor)
		}
	}
}

func gateC1bRouters(t *testing.T, topology *n2dTopology, profile gateC1bProfile) (*gateB2NATRouter, *gateB2NATRouter) {
	left := gateB2NATConfig{namespace: topology.natA, tunName: gateB2TUNName(topology.natA), mode: gateB2NATAPDM,
		private: netip.MustParseAddr(n2dClientAAddress), public: netip.MustParseAddr(n2dNATAWAN), peerPublic: netip.MustParseAddr(n2dNATBWAN)}
	right := gateB2NATConfig{namespace: topology.natB, tunName: gateB2TUNName(topology.natB), mode: gateB2NATAPDM,
		private: netip.MustParseAddr(n2dClientBAddress), public: netip.MustParseAddr(n2dNATBWAN), peerPublic: netip.MustParseAddr(n2dNATAWAN)}
	if profile.profile == hardnatplan.ProfileAsymmetricBirthday {
		ports := newGateB2FavorablePorts()
		right.mode, right.recordTargets, left.useFavorable = gateB2NATEIM, ports, ports
	}
	if profile.profile == hardnatplan.ProfileHardBirthday {
		left, right = gateB3RouterConfig(topology, true, 11, 0), gateB3RouterConfig(topology, false, 29, 0)
		lateHit := newGateB3LateHitMappingPlan()
		left.gateB3MappingPlan, left.gateB3MappingPlanLeft, right.gateB3MappingPlan = lateHit, true, lateHit
	}
	return startGateB2NATRouter(t, left), startGateB2NATRouter(t, right)
}

func gateC1bFixture(t *testing.T, topology *n2dTopology, observer hardnatobserve.Topology, profile gateC1bProfile, loopbackSSH bool) [2]gateC1bHostConfig {
	return gateC1bFixtureForFault(t, topology, observer, profile, loopbackSSH, "")
}

func gateC1bFixtureForFault(t *testing.T, topology *n2dTopology, observer hardnatobserve.Topology, profile gateC1bProfile, loopbackSSH bool, fault string) [2]gateC1bHostConfig {
	t.Helper()
	ipBinary, err := exec.LookPath("ip")
	if err != nil || !filepath.IsAbs(ipBinary) {
		t.Fatal("Gate C1b private interface helper unavailable")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal("Gate C1b private fixture permissions failed")
	}
	write := func(path string, payload []byte) {
		t.Helper()
		if err := pairgen.WritePrivateFileExclusive(path, payload); err != nil {
			t.Fatal("Gate C1b private fixture write failed")
		}
	}
	clientKey, clientPublic := gateC1bSSHKey(t)
	hostKey, hostPublic := gateC1bSSHKey(t)
	defer clear(clientKey)
	defer clear(hostKey)
	identity, known, host := filepath.Join(directory, "identity"), filepath.Join(directory, "known"), filepath.Join(directory, "host")
	endpoint, listen, serverNamespace := n2dNATBWAN, n2dClientBAddress, topology.clientB
	if loopbackSSH {
		endpoint, listen, serverNamespace = "127.0.0.1", "127.0.0.1", topology.clientA
	}
	write(identity, clientKey)
	write(host, hostKey)
	write(known, []byte(endpoint+" "+string(hostPublic)))
	sshdFile := filepath.Join(directory, "sshd_config")
	write(sshdFile, []byte(fmt.Sprintf(`Port 22
ListenAddress %s
HostKey %s
AuthorizedKeysFile /root/.ssh/authorized_keys
PidFile none
PermitRootLogin forced-commands-only
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitUserEnvironment no
DisableForwarding yes
PermitTTY no
PermitUserRC no
UsePAM no
UseDNS no
PrintMotd no
PrintLastLog no
LogLevel VERBOSE
LoginGraceTime 3
MaxSessions 1
AllowUsers root
`, listen, host)))
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	label := profile.name + "/" + endpoint
	psk := sha256.Sum256([]byte("gate-c1b-synthetic/" + label))
	set, err := gatecattempt.EncodeArtifactSet(gatecattempt.ArtifactMaterial{
		CredentialID: n2dOpaqueID(label + "/credential"), AttemptID: n2dOpaqueID(label + "/attempt"),
		InitiatorParticipantID: n2dOpaqueID(label + "/initiator"), ResponderParticipantID: n2dOpaqueID(label + "/responder"), OOBChannelID: n2dOpaqueID(label + "/channel"),
		PlannerProfile: profile.profile, ResourceClass: profile.resource, InitiatorPlannerRole: profile.plannerRoles[0], ResponderPlannerRole: profile.plannerRoles[1],
		IssuedAt: issued, ExpiresAt: issued.Add(10 * time.Minute),
	}, psk)
	clear(psk[:])
	if err != nil {
		t.Fatal("Gate C1b synthetic artifact generation failed")
	}
	defer set.Close()
	var parentMount unix.Stat_t
	if unix.Stat("/proc/self/ns/mnt", &parentMount) != nil {
		t.Fatal("Gate C1b mount identity unavailable")
	}
	private := [2]tunnel.PrivateKey{}
	for index := range private {
		private[index], err = tunnel.GeneratePrivateKey()
		if err != nil {
			t.Fatal("Gate C1b synthetic WireGuard material failed")
		}
	}
	observers, err := observer.Endpoints()
	if err != nil {
		t.Fatal("Gate C1b observer topology rejected")
	}
	var result [2]gateC1bHostConfig
	for index := range result {
		sideDir := filepath.Join(directory, fmt.Sprintf("side-%d", index))
		if os.Mkdir(sideDir, 0o700) != nil {
			t.Fatal("Gate C1b endpoint fixture setup failed")
		}
		cfg := gateC1bHostConfig{Server: index == 1, Fault: fault, UseTUN: !loopbackSSH, ParentMount: parentMount.Ino, SSHDConfig: sshdFile, SSHDBinary: gateC1bSSHDPath(t), IPBinary: ipBinary, Observers: observers,
			MachineBase: filepath.Join(sideDir, "machine-base"), InstallBase: filepath.Join(sideDir, "install-base"), HomeDirectory: filepath.Join(sideDir, "private-home"), ShadowFile: filepath.Join(sideDir, "shadow"),
			RuntimeBase: filepath.Join(sideDir, "runtime"),
			RequestFile: filepath.Join(sideDir, "request.json"), ConfigFile: filepath.Join(sideDir, "config.yaml"), ResultFile: filepath.Join(sideDir, "result.json"),
			ReadyFile: filepath.Join(sideDir, "ready"), StageFile: filepath.Join(sideDir, "stage"), StopFile: filepath.Join(sideDir, "stop")}
		cfg.Namespace, cfg.HostNamespace, cfg.Side, cfg.SSHSide = topology.clientA, topology.clientA, probeio.GateB2NATLabLeft, sshassembly.NATLabRight
		if index == 1 {
			cfg.Namespace, cfg.HostNamespace, cfg.Side, cfg.SSHSide = topology.clientB, serverNamespace, probeio.GateB2NATLabRight, sshassembly.NATLabLeft
		}
		for _, path := range []string{cfg.MachineBase, cfg.InstallBase, cfg.HomeDirectory, filepath.Join(cfg.InstallBase, "winkyou"),
			cfg.RuntimeBase, filepath.Join(cfg.RuntimeBase, "sshd"), filepath.Join(cfg.RuntimeBase, "netns")} {
			if os.Mkdir(path, 0o755) != nil {
				t.Fatal("Gate C1b private mount directory failed")
			}
		}
		if os.Chmod(cfg.HomeDirectory, 0o700) != nil {
			t.Fatal("Gate C1b private home permissions failed")
		}
		if cfg.Server {
			// StrictModes walks parent directories to the home/root boundary.
			// A private file below the shared temp ancestor is insufficient.
			// This directory is visible as /root only in the existing private
			// mount namespace; the host's SSH home is never read or changed.
			keyDirectory := filepath.Join(cfg.HomeDirectory, ".ssh")
			if os.Mkdir(keyDirectory, 0o700) != nil {
				t.Fatal("Gate C1b private authorized-key directory failed")
			}
			write(filepath.Join(keyDirectory, "authorized_keys"), []byte(sshchildwrapper.AuthorizedKeyOptions()+" "+string(clientPublic)))
		}
		write(cfg.ShadowFile, []byte("root:x:19000:0:99999:7:::\n")) // Non-password fixture; password authentication is disabled.
		for _, name := range []string{"wink", "gate-c-child-wrapper"} {
			copyGateC1bBinary(t, os.Args[0], filepath.Join(cfg.InstallBase, "winkyou", name))
		}
		artifactPath := filepath.Join(sideDir, "artifact.json")
		write(artifactPath, [][]byte{set.Initiator, set.Responder}[index])
		virtual := [2]string{"192.0.2.100", "192.0.2.101"}
		productConfig := config.Default()
		productConfig.Node.Name = fmt.Sprintf("synthetic-endpoint-%d", index)
		productConfig.NAT.STUNServers = nil
		productConfig.WireGuard.PrivateKey = private[index].String()
		productConfig.GateC.Peers = []config.GateCPeerConfig{{Ref: "private-peer", PublicKey: private[1-index].PublicKey().String(),
			AllowedIPs: []string{virtual[1-index] + "/32"}, LocalVirtualIP: virtual[index], PeerVirtualIP: virtual[1-index],
			MemoryInterfaceName: "wink-c1b-proof", MemoryMTU: 1280, SessionCeiling: 8 * time.Second}}
		if fault == "wireguard-failure" && index == 0 {
			wrongKey, err := tunnel.GeneratePrivateKey()
			if err != nil {
				t.Fatal("synthetic wrong-key fixture failed")
			}
			productConfig.GateC.Peers[0].PublicKey = wrongKey.PublicKey().String()
		}
		encodedConfig, err := yaml.Marshal(productConfig)
		if err != nil {
			t.Fatal("Gate C1b private configuration encoding failed")
		}
		write(cfg.ConfigFile, encodedConfig)
		write(filepath.Join(cfg.HomeDirectory, "config.yaml"), encodedConfig)
		clear(encodedConfig)
		request := gatecrequest.Request{Role: []gatecattempt.Role{gatecattempt.RoleInitiator, gatecattempt.RoleResponder}[index],
			ArtifactFile: artifactPath, PeerRef: "private-peer", ExpectedPeerPublicAddress: netip.MustParseAddr([]string{n2dNATBWAN, n2dNATAWAN}[index]),
			ObserverSet: gatecrequest.ObserverSet{Primary: observers[0], AlternatePort: observers[1], AlternateAddress: observers[2], AlternateAddressPort: observers[3]}}
		if index == 0 {
			request.SSH = &gatecrequest.SSHConfig{Endpoint: netip.AddrPortFrom(netip.MustParseAddr(endpoint), 22), User: "root", IdentityFile: identity, KnownHostsFile: known}
		}
		encodedRequest, err := gatecrequest.Encode(request)
		if err != nil {
			t.Fatal("Gate C1b private request encoding failed")
		}
		write(cfg.RequestFile, encodedRequest)
		clear(encodedRequest)
		result[index] = cfg
	}
	return result
}

func gateC1bSSHKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Gate C1b synthetic SSH key generation failed")
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "synthetic-c1b-proof")
	if err != nil {
		t.Fatal("Gate C1b private SSH key encoding failed")
	}
	defer clear(block.Bytes)
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal("Gate C1b public SSH key encoding failed")
	}
	return pem.EncodeToMemory(block), ssh.MarshalAuthorizedKey(key)
}

func copyGateC1bBinary(t *testing.T, source, target string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal("Gate C1b source binary unavailable")
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal("Gate C1b private executable creation failed")
	}
	_, copyErr := io.Copy(output, input)
	syncErr, closeErr := output.Sync(), output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || os.Chmod(target, 0o700) != nil {
		t.Fatal("Gate C1b private executable copy failed")
	}
}

type gateC1bHostProcess struct {
	command *exec.Cmd
	done    chan struct{}
	config  gateC1bHostConfig
	waitErr error
	mu      sync.Mutex
}

func startGateC1bHost(t *testing.T, cfg gateC1bHostConfig) *gateC1bHostProcess {
	t.Helper()
	configPath := cfg.RequestFile + ".harness"
	if writeN1JSON(configPath, cfg) != nil {
		t.Fatal("Gate C1b host metadata failed")
	}
	command := exec.Command("ip", "netns", "exec", cfg.HostNamespace, os.Args[0], "-test.run=^TestGateC1bHostProcess$", "-test.count=1", "-test.timeout=80s")
	command.Env = append(os.Environ(), gateC1bHostEnv+"=1", gateC1bHostConfigEnv+"="+configPath)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL, Setpgid: true}
	process := &gateC1bHostProcess{command: command, config: cfg, done: make(chan struct{})}
	finished, err := startGateC1bOwnedProcess(command)
	if err != nil {
		t.Fatal("Gate C1b isolated host start failed")
	}
	go func() {
		err := <-finished
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		select {
		case <-process.done:
			return
		default:
		}
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case <-process.done:
		case <-time.After(2 * time.Second):
			t.Error("Gate C1b host cleanup did not drain")
		}
	})
	return process
}

func (process *gateC1bHostProcess) waitFile(t *testing.T, path string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-process.done:
			var result gateC1bProcessResult
			// The process can publish then exit between the Stat and select.
			// Let the caller inspect that terminal result (including the peer).
			if _, err := os.Stat(path); err == nil {
				return
			}
			if readN1JSON(process.config.ResultFile, &result) {
				t.Fatalf("Gate C1b helper exited: class=%s stage=%s stages=%v", result.Class, result.Stage, result.Stages)
			}
			t.Fatal("Gate C1b helper exited before its private witness")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("Gate C1b private witness deadline exceeded")
}

func (process *gateC1bHostProcess) wait(t *testing.T) {
	t.Helper()
	select {
	case <-process.done:
	case <-time.After(3 * time.Second):
		t.Fatal("Gate C1b endpoint did not drain")
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.waitErr != nil {
		t.Fatal("Gate C1b host terminal failed")
	}
}

func (process *gateC1bHostProcess) stop(t *testing.T) {
	t.Helper()
	if os.WriteFile(process.config.StopFile, []byte("stop\n"), 0o600) != nil {
		t.Fatal("Gate C1b host stop witness failed")
	}
	process.wait(t)
}
