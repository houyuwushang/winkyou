package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/pkg/version"
)

type passiveDiagnoseRunner interface {
	Run(context.Context, passivediagnose.Options) passivediagnose.Report
}

func newDiagnoseCmd(opts *Options) *cobra.Command {
	return newDiagnoseCmdWithRunner(opts, passivediagnose.SystemInspector(version.Version))
}

func newDiagnoseCmdWithRunner(opts *Options, runner passiveDiagnoseRunner) *cobra.Command {
	var asJSON bool
	var governorScope string
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Collect passive first-run safety and network diagnostics",
		Long: "Collect configuration, interface, route, machine-owner, and safety state without starting a runtime or performing active network probes. " +
			"Missing machine scope is reported as active_probe_blocked rather than preventing passive output. " +
			"Portable users may explicitly prove the lower per-user authority with --governor-scope=user-acknowledged; it is never selected from config or environment.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			if asJSON {
				return writeJSON(cmd, report)
			}
			writePassiveDiagnoseReport(cmd, report)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output the passive report as json")
	cmd.Flags().StringVar(&governorScope, "governor-scope", string(governor.ScopeMachine), "safety scope: machine or explicit user-acknowledged")
	return cmd
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
	cmd.Println("No WinkYou runtime or active network activity was started.")
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
