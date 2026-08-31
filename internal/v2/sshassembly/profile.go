package sshassembly

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
)

const (
	WindowsOpenSSHPath = `C:\Windows\System32\OpenSSH\ssh.exe`
	LinuxOpenSSHPath   = `/usr/bin/ssh`
	FixedRemoteCommand = "wink solver direct child --stdio"

	ConnectTimeout = 3 * time.Second
	DrainTimeout   = 2 * time.Second
	MaxStderrBytes = 4 * 1024
)

type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
)

type SSHAssemblyCost struct {
	OwnedChildren          int
	OutboundTCPConnections int
	DNSResolutions         int
	Retries                int
	QueuedAttempts         int
}

var ExactAssemblyCost = SSHAssemblyCost{
	OwnedChildren: 1, OutboundTCPConnections: 1, DNSResolutions: 0, Retries: 0, QueuedAttempts: 0,
}

type ClientConfig struct {
	authority      SSHEndpointAuthority
	endpoint       netip.AddrPort
	user           string
	identityFile   string
	knownHostsFile string
}

var sshUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,63}$`)

// BindClientConfig validates local private inputs and binds the parsed request
// endpoint to a separately constructed sealed authority. The request endpoint
// never becomes authority on its own.
func BindClientConfig(authority SSHEndpointAuthority, local gatecrequest.SSHConfig) (ClientConfig, error) {
	if authority == nil || authority.validate() != nil || canonicalEndpoint(local.Endpoint) != authority.Endpoint() ||
		!sshUserPattern.MatchString(local.User) || !filepath.IsAbs(local.IdentityFile) || !filepath.IsAbs(local.KnownHostsFile) {
		return ClientConfig{}, ErrProfileInvalid
	}
	if err := validatePrivateClientFiles(local.IdentityFile, local.KnownHostsFile); err != nil {
		return ClientConfig{}, err
	}
	return ClientConfig{
		authority: authority, endpoint: authority.Endpoint(), user: local.User,
		identityFile: local.IdentityFile, knownHostsFile: local.KnownHostsFile,
	}, nil
}

func validatePrivateClientFiles(identityFile, knownHostsFile string) error {
	identity, err := pairgen.ReadPrivateFile(identityFile, 64*1024)
	if err != nil || len(identity) == 0 {
		clear(identity)
		return ErrProfileInvalid
	}
	clear(identity)
	known, err := pairgen.ReadPrivateFile(knownHostsFile, 16*1024)
	if err != nil || len(known) == 0 {
		clear(known)
		return ErrProfileInvalid
	}
	normalized := strings.TrimSuffix(string(known), "\n")
	if strings.HasSuffix(normalized, "\r") {
		normalized = strings.TrimSuffix(normalized, "\r")
	}
	valid := normalized != "" && !strings.ContainsAny(normalized, "\r\n") && strings.TrimSpace(normalized) == normalized
	clear(known)
	if !valid {
		return ErrProfileInvalid
	}
	return nil
}

func activeDuration(profile hardnatplan.Profile, resource hardnatplan.ResourceClass) (time.Duration, error) {
	return hardnatbudget.ActiveDuration(profile, resource)
}

func executableFor(platform Platform) (string, error) {
	switch platform {
	case PlatformWindows:
		return WindowsOpenSSHPath, nil
	case PlatformLinux:
		return LinuxOpenSSHPath, nil
	default:
		return "", ErrProfileInvalid
	}
}

func currentPlatform() (Platform, error) {
	switch runtime.GOOS {
	case "windows":
		return PlatformWindows, nil
	case "linux":
		return PlatformLinux, nil
	default:
		return "", ErrProfileInvalid
	}
}

func fixedEnvironment(platform Platform) ([]string, error) {
	switch platform {
	case PlatformWindows:
		return []string{`SYSTEMROOT=C:\Windows`, `WINDIR=C:\Windows`, `PROGRAMDATA=C:\ProgramData`}, nil
	case PlatformLinux:
		return []string{"LANG=C", "LC_ALL=C"}, nil
	default:
		return nil, ErrProfileInvalid
	}
}

func buildArguments(config ClientConfig) ([]string, error) {
	if config.authority == nil || config.authority.validate() != nil || config.endpoint != config.authority.Endpoint() ||
		canonicalEndpoint(config.endpoint) != config.endpoint || !sshUserPattern.MatchString(config.user) {
		return nil, ErrProfileInvalid
	}
	endpoint := config.authority.Endpoint()
	options := []string{
		"BatchMode=yes", "NumberOfPasswordPrompts=0", "PasswordAuthentication=no",
		"KbdInteractiveAuthentication=no", "GSSAPIAuthentication=no", "PubkeyAuthentication=yes",
		"IdentitiesOnly=yes", "IdentityAgent=none", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
		"VerifyHostKeyDNS=no", "CheckHostIP=no", "UserKnownHostsFile=" + config.knownHostsFile,
		"GlobalKnownHostsFile=none", "ControlMaster=no", "ControlPersist=no", "ControlPath=none",
		"ProxyCommand=none", "ProxyJump=none", "CanonicalizeHostname=no", "ClearAllForwardings=yes",
		"ForwardAgent=no", "ForwardX11=no", "Tunnel=no", "PermitLocalCommand=no", "SessionType=default",
		"EscapeChar=none", "ConnectionAttempts=1", "ConnectTimeout=" + strconv.Itoa(int(ConnectTimeout/time.Second)),
		"User=" + config.user,
	}
	arguments := []string{"-F", "none", "-T", "-i", config.identityFile, "-p", strconv.Itoa(int(endpoint.Port()))}
	for _, option := range options {
		arguments = append(arguments, "-o", option)
	}
	arguments = append(arguments, endpoint.Addr().String(), FixedRemoteCommand)
	return arguments, nil
}

func validateNoForbiddenArgument(arguments []string) error {
	joined := " " + strings.Join(arguments, " ") + " "
	for _, forbidden := range []string{" -L ", " -R ", " -D ", " -W ", " -N ", " -s ", "ProxyCommand=exec:"} {
		if strings.Contains(joined, forbidden) {
			return fmt.Errorf("%w: forbidden fixed argument", ErrProfileInvalid)
		}
	}
	return nil
}
