package cmd

import (
	"context"
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
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Collect passive first-run safety and network diagnostics",
		Long: "Collect configuration, interface, route, machine-owner, and safety state without starting a runtime or performing active network probes. " +
			"Missing machine scope is reported as active_probe_blocked rather than preventing passive output.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath := ""
			if opts != nil {
				configPath = opts.ConfigPath
			}
			report := runner.Run(cmd.Context(), passivediagnose.Options{ConfigPath: configPath})
			if asJSON {
				return writeJSON(cmd, report)
			}
			writePassiveDiagnoseReport(cmd, report)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output the passive report as json")
	return cmd
}

func writePassiveDiagnoseReport(cmd *cobra.Command, report passivediagnose.Report) {
	cmd.Printf("WinkYou passive diagnose (%s)\n", report.SchemaVersion)
	cmd.Printf("Generated:       %s\n", report.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"))
	cmd.Printf("Build:           %s\n", dashIfEmpty(report.BuildVersion))
	cmd.Printf("Redaction:       %s (not yet export_redacted_report)\n", dashIfEmpty(report.Redaction))
	cmd.Printf("Platform:        %s/%s\n", dashIfEmpty(report.Platform.OS), dashIfEmpty(report.Platform.Arch))
	cmd.Printf("Governor scope:  %s\n", report.GovernorScope)
	cmd.Printf("Machine scope:   %s (ready=%t)\n", report.Namespace.State, report.Namespace.Ready)
	if report.Namespace.Detail != "" {
		cmd.Printf("Scope detail:    %s\n", report.Namespace.Detail)
	}
	writePassiveOwner(cmd, report.Owner)
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
	cmd.Printf("Machine owner:   %s (held=%t)\n", status.State, status.Held)
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

var _ passiveDiagnoseRunner = passivediagnose.Inspector{}
