package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stunobserve"
	"winkyou/pkg/version"
)

type passiveDiagnoseRunner interface {
	Run(context.Context, passivediagnose.Options) passivediagnose.Report
}

type activeSTUNRunner interface {
	Run(context.Context, passivediagnose.ActiveSTUNOptions) (passivediagnose.ActiveSTUNReport, error)
}

func newDiagnoseCmd(opts *Options) *cobra.Command {
	return newDiagnoseCmdWithRunners(
		opts,
		passivediagnose.SystemInspector(version.Version),
		passivediagnose.SystemActiveSTUNInspector(version.Version),
	)
}

func newDiagnoseCmdWithRunner(opts *Options, runner passiveDiagnoseRunner) *cobra.Command {
	return newDiagnoseCmdWithRunners(opts, runner, passivediagnose.SystemActiveSTUNInspector(version.Version))
}

func newDiagnoseCmdWithRunners(opts *Options, runner passiveDiagnoseRunner, activeRunner activeSTUNRunner) *cobra.Command {
	var asJSON bool
	var governorScope string
	var activeSTUNValues []string
	var mapBehavior bool
	var portAllocationSockets int
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Collect passive diagnostics or explicitly request bounded STUN observations",
		Long: "Collect configuration, interface, route, machine-owner, and safety state without starting a runtime or performing active network probes. " +
			"Missing machine scope is reported as active_probe_blocked rather than preventing passive output. " +
			"Portable users may explicitly prove the lower per-user authority with --governor-scope=user-acknowledged; it is never selected from config or environment. " +
			"Active STUN is off by default and requires one to three literal IP:port --active-stun flags.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			if len(args) == 1 && cmd.Flags().Changed("port-allocation") {
				return nil
			}
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			portAllocationRequested := cmd.Flags().Changed("port-allocation")
			if len(args) == 1 {
				if !portAllocationRequested || portAllocationSockets != stunobserve.DefaultAllocationSockets {
					return fmt.Errorf("unexpected diagnose argument %q", args[0])
				}
				value, parseErr := strconv.Atoi(args[0])
				if parseErr != nil {
					return fmt.Errorf("invalid --port-allocation value %q: use an integer", args[0])
				}
				portAllocationSockets = value
			}
			targets, err := parseActiveSTUNTargets(activeSTUNValues)
			if err != nil {
				return err
			}
			if mapBehavior && portAllocationRequested {
				return fmt.Errorf("--map-behavior and --port-allocation are mutually exclusive")
			}
			if mapBehavior {
				if err := passivediagnose.ValidateMappingBehaviorTargets(targets); err != nil {
					return err
				}
			}
			if portAllocationRequested {
				if err := passivediagnose.ValidatePortAllocationRequest(targets, portAllocationSockets); err != nil {
					return err
				}
			}
			scope := governor.ScopeMachine
			switch governorScope {
			case string(governor.ScopeMachine):
			case "user-acknowledged":
				scope = governor.ScopeUserAcknowledged
				cmd.PrintErrln(passivediagnose.UserAcknowledgedWarning)
			default:
				return fmt.Errorf("invalid --governor-scope %q: use machine or user-acknowledged", governorScope)
			}
			configPath := ""
			if opts != nil {
				configPath = opts.ConfigPath
			}
			report := runner.Run(cmd.Context(), passivediagnose.Options{ConfigPath: configPath, GovernorScope: scope})
			var activeErr error
			if len(targets) > 0 {
				if activeRunner == nil {
					return fmt.Errorf("active STUN runner is unavailable")
				}
				cmd.PrintErrln(passivediagnose.ActiveSTUNDisclosure)
				active, err := activeRunner.Run(cmd.Context(), passivediagnose.ActiveSTUNOptions{
					Targets:               targets,
					GovernorScope:         scope,
					MapBehavior:           mapBehavior,
					PortAllocationSockets: portAllocationSockets,
				})
				passivediagnose.ApplyActiveSTUN(&report, active)
				activeErr = err
			}
			if asJSON {
				if err := writeJSON(cmd, report); err != nil {
					return err
				}
				return activeErr
			}
			writePassiveDiagnoseReport(cmd, report)
			return activeErr
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output the diagnostic report as json")
	cmd.Flags().StringVar(&governorScope, "governor-scope", string(governor.ScopeMachine), "safety scope: machine or explicit user-acknowledged")
	cmd.Flags().StringArrayVar(&activeSTUNValues, "active-stun", nil, "explicit literal STUN target IP:port (repeat up to 3 times; sends UDP)")
	cmd.Flags().BoolVar(&mapBehavior, "map-behavior", false, "reuse one governed socket across 2-3 active STUN targets")
	cmd.Flags().IntVar(&portAllocationSockets, "port-allocation", 0, "observe one target through 3-8 governed sockets (default 5 when flag has no value)")
	cmd.Flags().Lookup("port-allocation").NoOptDefVal = strconv.Itoa(stunobserve.DefaultAllocationSockets)
	return cmd
}

func parseActiveSTUNTargets(values []string) ([]netip.AddrPort, error) {
	if len(values) > passivediagnose.MaxActiveSTUNTargets {
		return nil, fmt.Errorf("too many --active-stun targets: got %d, maximum %d", len(values), passivediagnose.MaxActiveSTUNTargets)
	}
	targets := make([]netip.AddrPort, 0, len(values))
	seen := make(map[netip.AddrPort]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != value || value == "" {
			return nil, fmt.Errorf("invalid --active-stun %q: use a literal IP:port", value)
		}
		target, err := netip.ParseAddrPort(value)
		if err != nil || target.Port() == 0 || target.Addr().Zone() != "" {
			return nil, fmt.Errorf("invalid --active-stun %q: use a literal IP:port with a non-zero port; DNS names are not accepted", value)
		}
		target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
		if target.Addr().IsUnspecified() || target.Addr().IsMulticast() || (!target.Addr().IsLoopback() && !target.Addr().IsGlobalUnicast()) {
			return nil, fmt.Errorf("invalid --active-stun %q: address must be unicast", value)
		}
		if _, exists := seen[target]; exists {
			return nil, fmt.Errorf("duplicate --active-stun target %q", value)
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

func writePassiveDiagnoseReport(cmd *cobra.Command, report passivediagnose.Report) {
	cmd.Printf("WinkYou passive diagnose (%s)\n", report.SchemaVersion)
	cmd.Printf("Generated:       %s\n", report.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"))
	cmd.Printf("Build:           %s\n", dashIfEmpty(report.BuildVersion))
	cmd.Printf("Redaction:       %s (not yet export_redacted_report)\n", dashIfEmpty(report.Redaction))
	cmd.Printf("Platform:        %s/%s\n", dashIfEmpty(report.Platform.OS), dashIfEmpty(report.Platform.Arch))
	cmd.Printf("Governor scope:  %s\n", report.GovernorScope)
	scopeLabel := "Machine scope"
	if report.GovernorScope == governor.ScopeUserAcknowledged {
		scopeLabel = "User scope"
	}
	cmd.Printf("%-16s %s (ready=%t)\n", scopeLabel+":", report.Namespace.State, report.Namespace.Ready)
	if report.Namespace.Detail != "" {
		cmd.Printf("Scope detail:    %s\n", report.Namespace.Detail)
	}
	writePassiveOwner(cmd, report.Owner)
	if report.MachineNamespace != nil {
		cmd.Printf("Machine scope:   %s (ready=%t; not bypassed silently)\n", report.MachineNamespace.State, report.MachineNamespace.Ready)
	}
	if boundary := report.UserAcknowledged; boundary != nil {
		cmd.Printf("Explicit ack:    %t (machine_wide=%t persistent_default=%t)\n", boundary.ExplicitAcknowledgement, boundary.MachineWide, boundary.PersistentDefault)
		cmd.Printf("Scope lifecycle: acquired=%t policy_verified=%t released=%t profile=%s\n", boundary.Acquired, boundary.PolicyVerified, boundary.Released, boundary.Profile)
		cmd.Printf("Scope allowlist: %s\n", joinOperations(boundary.AllowedOperations))
		cmd.Printf(
			"Scope hard cap: peers=%d attempts=%d heavyweight=%d duration_ms=%d drain_ms=%d\n",
			boundary.HardLimits.MaxActivePeers,
			boundary.HardLimits.MaxActiveAttempts,
			boundary.HardLimits.MaxHeavyweightAttempts,
			boundary.HardLimits.MaxAttemptDurationMS,
			boundary.HardLimits.CancellationDrainTimeoutMS,
		)
		cmd.Printf(
			"Scope resources: sockets=%d targets=%d pps=%d packets=%d five_tuples=%d\n",
			boundary.HardLimits.Aggregate.Sockets,
			boundary.HardLimits.Aggregate.Targets,
			boundary.HardLimits.Aggregate.PacketsPerSecond,
			boundary.HardLimits.Aggregate.Packets,
			boundary.HardLimits.Aggregate.FiveTuples,
		)
		cmd.Printf("Scope denied:    %s\n", strings.Join(boundary.DeniedCapabilities, ","))
		if boundary.Detail != "" {
			cmd.Printf("Boundary detail: %s\n", boundary.Detail)
		}
	}
	cmd.Printf("Safety trip:     %s (blocks_active_work=%t)\n", report.SafetyTrip.State, report.SafetyTrip.BlocksActiveWork)
	if report.SafetyTrip.Detail != "" {
		cmd.Printf("Safety detail:   %s\n", report.SafetyTrip.Detail)
	}
	cmd.Printf("Configuration:   %s (source=%s file_present=%t)\n", report.Configuration.State, report.Configuration.Source, report.Configuration.FilePresent)
	if report.Configuration.Detail != "" {
		cmd.Printf("Config detail:   %s\n", report.Configuration.Detail)
	}
	cmd.Printf("Interfaces:      %s (count=%d up=%d; addresses redacted)\n", report.Interfaces.State, report.Interfaces.Count, report.Interfaces.UpCount)
	for _, networkInterface := range report.Interfaces.Interfaces {
		classes := "-"
		if len(networkInterface.AddressClasses) > 0 {
			classes = strings.Join(networkInterface.AddressClasses, ",")
		}
		cmd.Printf("  - %q index=%d mtu=%d up=%t loopback=%t address_classes=%s\n", networkInterface.Name, networkInterface.Index, networkInterface.MTU, networkInterface.Up, networkInterface.Loopback, classes)
	}
	if report.Interfaces.Detail != "" {
		cmd.Printf("Interface detail: %s\n", report.Interfaces.Detail)
	}
	cmd.Printf("Default route:   %s", report.DefaultRoute.State)
	if report.DefaultRoute.Family != "" {
		cmd.Printf(" family=%s", report.DefaultRoute.Family)
	}
	if report.DefaultRoute.Interface != "" {
		cmd.Printf(" interface=%q", report.DefaultRoute.Interface)
	}
	cmd.Println()
	if report.DefaultRoute.Detail != "" {
		cmd.Printf("Route detail:    %s\n", report.DefaultRoute.Detail)
	}
	cmd.Printf("Active probe:    %s (reason=%s)\n", report.ActiveProbe.State, report.ActiveProbe.Reason)
	cmd.Printf("Probe detail:    %s\n", report.ActiveProbe.Detail)
	if report.ActiveProbe.Action != "" {
		cmd.Printf("Action:          %s\n", report.ActiveProbe.Action)
	}
	cmd.Printf("Network started: %t\n", report.NetworkActivityStarted)
	if report.ActiveSTUN == nil {
		cmd.Println("No WinkYou runtime or active network activity was started.")
		return
	}
	writeActiveSTUNReport(cmd, *report.ActiveSTUN)
	cmd.Println("No WinkYou runtime was started; active STUN was limited to the explicitly listed targets.")
}

func writeActiveSTUNReport(cmd *cobra.Command, report passivediagnose.ActiveSTUNReport) {
	cmd.Printf("Active STUN:     %s (targets=%d scope=%s)\n", report.State, report.TargetCount, report.ObservationScope)
	cmd.Printf("Worst-case:      duration_ms=%d packets=%d transmissions_per_target=%d\n", report.WorstCaseDurationMS, report.WorstCasePackets, report.MaxTransmissionsPerTarget)
	if report.ErrorClass != "" {
		cmd.Printf("STUN error:      %s (reason=%s)\n", report.ErrorClass, report.Reason)
	}
	results := report.Results
	if allocation := report.PortAllocation; allocation != nil {
		limitations := "none"
		if len(allocation.Limitations) > 0 {
			values := make([]string, 0, len(allocation.Limitations))
			for _, limitation := range allocation.Limitations {
				values = append(values, string(limitation))
			}
			limitations = strings.Join(values, ",")
		}
		deltas := "none"
		if len(allocation.Deltas) > 0 {
			values := make([]string, 0, len(allocation.Deltas))
			for _, delta := range allocation.Deltas {
				values = append(values, strconv.Itoa(delta))
			}
			deltas = strings.Join(values, ",")
		}
		cmd.Printf("Port allocation: %s (scope=%s successes=%d/%d limitations=%s deltas=%s)\n", allocation.Behavior, allocation.EvidenceScope, allocation.SuccessfulSockets, allocation.TotalSockets, limitations, deltas)
		for index, result := range allocation.Results {
			cmd.Printf("  - socket=%d local=%s target=%s duration_ms=%d transmissions=%d scope=%s", index+1, dashIfEmpty(result.LocalAddress), dashIfEmpty(result.Target), result.DurationMS, result.Transmissions, result.ObservationScope)
			if result.MappedAddress != "" {
				cmd.Printf(" mapped=%s port_behavior=%s", result.MappedAddress, result.PortBehavior)
			}
			if result.ErrorClass != "" {
				cmd.Printf(" error=%s reason=%s", result.ErrorClass, result.Reason)
			}
			cmd.Println()
		}
		return
	}
	if mapping := report.MappingBehavior; mapping != nil {
		limitations := "none"
		if len(mapping.Limitations) > 0 {
			values := make([]string, 0, len(mapping.Limitations))
			for _, limitation := range mapping.Limitations {
				values = append(values, string(limitation))
			}
			limitations = strings.Join(values, ",")
		}
		cmd.Printf("Mapping behavior: %s (scope=%s successes=%d limitations=%s)\n", mapping.Behavior, mapping.EvidenceScope, mapping.SuccessfulTargets, limitations)
		results = mapping.Results
	}
	for _, result := range results {
		cmd.Printf("  - target=%s duration_ms=%d transmissions=%d scope=%s", dashIfEmpty(result.Target), result.DurationMS, result.Transmissions, result.ObservationScope)
		if result.MappedAddress != "" {
			cmd.Printf(" mapped=%s port_behavior=%s", result.MappedAddress, result.PortBehavior)
		}
		if result.ErrorClass != "" {
			cmd.Printf(" error=%s reason=%s", result.ErrorClass, result.Reason)
		}
		cmd.Println()
	}
}

func writePassiveOwner(cmd *cobra.Command, status governor.OwnerStatus) {
	label := "Machine owner"
	if status.Scope == governor.ScopeUserAcknowledged {
		label = "User owner"
	}
	cmd.Printf("%-16s %s (held=%t)\n", label+":", status.State, status.Held)
	if status.Owner != nil {
		cmd.Printf(
			"Owner detail:    pid=%d instance=%s build=%s scope=%s\n",
			status.Owner.PID,
			dashIfEmpty(status.Owner.InstanceID),
			dashIfEmpty(status.Owner.BuildVersion),
			status.Owner.Scope,
		)
	} else if strings.TrimSpace(status.Detail) != "" {
		cmd.Printf("Owner detail:    %s\n", status.Detail)
	}
}

func joinOperations(operations []governor.Operation) string {
	values := make([]string, 0, len(operations))
	for _, operation := range operations {
		values = append(values, string(operation))
	}
	return strings.Join(values, ",")
}

var _ passiveDiagnoseRunner = passivediagnose.Inspector{}
var _ activeSTUNRunner = passivediagnose.ActiveSTUNInspector{}
