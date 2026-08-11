package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"winkyou/internal/governor"
	"winkyou/pkg/version"
)

type safetyManager interface {
	Status() governor.SafetyTripStatus
	Reset(expectedSequence uint64, note string) (governor.SafetyTripStatus, error)
}

type systemSafetyManager struct{}

func (systemSafetyManager) Status() governor.SafetyTripStatus {
	return governor.InspectMachineSafetyTrip()
}

func (systemSafetyManager) Reset(expectedSequence uint64, note string) (governor.SafetyTripStatus, error) {
	return governor.ResetMachineSafetyTrip(expectedSequence, note, version.Version)
}

func newSafetyCmd() *cobra.Command {
	return newSafetyCmdWithManager(systemSafetyManager{})
}

func newSafetyCmdWithManager(manager safetyManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "safety",
		Short: "Inspect or explicitly reset the persistent machine safety trip",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(
		newSafetyStatusCmd(manager),
		newSafetyResetCmd(manager),
	)
	return cmd
}

func newSafetyStatusCmd(manager safetyManager) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Read the persistent safety trip without changing the machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status := manager.Status()
			if err := writeSafetyTripStatus(cmd, status, asJSON); err != nil {
				return err
			}
			if status.BlocksActiveWork {
				return &governor.SafetyTripError{Status: status}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output status as json")
	return cmd
}

func newSafetyResetCmd(manager safetyManager) *cobra.Command {
	var expectedSequence uint64
	var note string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset the exact trip sequence previously reviewed by an operator",
		Long: "Reset requires administrator/root privileges, an exact observed sequence, and an operator note. " +
			"It never starts a runtime or performs network activity.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if expectedSequence == 0 {
				return fmt.Errorf("%w: --expected-sequence must be greater than zero", governor.ErrSafetyResetRejected)
			}
			if strings.TrimSpace(note) == "" {
				return fmt.Errorf("%w: --note is required", governor.ErrSafetyResetRejected)
			}
			status, err := manager.Reset(expectedSequence, note)
			if status.State != "" {
				if outputErr := writeSafetyTripStatus(cmd, status, asJSON); outputErr != nil {
					return outputErr
				}
			}
			if err != nil {
				return fmt.Errorf("reset machine safety trip: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().Uint64Var(&expectedSequence, "expected-sequence", 0, "exact tripped sequence shown by safety status")
	cmd.Flags().StringVar(&note, "note", "", "operator review note recorded with the reset")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output status as json")
	return cmd
}

func writeSafetyTripStatus(cmd *cobra.Command, status governor.SafetyTripStatus, asJSON bool) error {
	if asJSON {
		return writeJSON(cmd, status)
	}
	cmd.Printf("Safety trip:       %s\n", status.State)
	cmd.Printf("Blocks active work: %t\n", status.BlocksActiveWork)
	if status.Record.Sequence > 0 {
		cmd.Printf("Sequence:          %d\n", status.Record.Sequence)
	}
	if !status.Record.UpdatedAt.IsZero() {
		cmd.Printf("Updated:           %s\n", status.Record.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	if status.Record.Reason != "" {
		cmd.Printf("Reason:            %s\n", status.Record.Reason)
	}
	if status.Record.Detail != "" {
		cmd.Printf("Detail:            %s\n", status.Record.Detail)
	}
	if status.Record.PeerID != "" {
		cmd.Printf("Peer:              %s\n", status.Record.PeerID)
	}
	if status.Record.AttemptID != "" {
		cmd.Printf("Attempt:           %s\n", status.Record.AttemptID)
	}
	if status.Record.BuildVersion != "" {
		cmd.Printf("Build:             %s\n", status.Record.BuildVersion)
	}
	if status.Record.ResetNote != "" {
		cmd.Printf("Reset note:        %s\n", status.Record.ResetNote)
	}
	if status.Detail != "" {
		cmd.Printf("State detail:      %s\n", status.Detail)
	}
	cmd.Println("No WinkYou runtime or network activity was started.")
	return nil
}
