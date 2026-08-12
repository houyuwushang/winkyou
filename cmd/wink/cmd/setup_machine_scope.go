package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"winkyou/internal/governor"
)

type machineScopeManager interface {
	Inspect() governor.NamespaceStatus
	Setup() (governor.NamespaceStatus, error)
}

type systemMachineScopeManager struct{}

func (systemMachineScopeManager) Inspect() governor.NamespaceStatus {
	return governor.InspectMachineNamespace()
}

func (systemMachineScopeManager) Setup() (governor.NamespaceStatus, error) {
	return governor.SetupMachineNamespace()
}

func newSetupMachineScopeCmd() *cobra.Command {
	return newSetupMachineScopeCmdWithManager(systemMachineScopeManager{})
}

func newSetupMachineScopeCmdWithManager(manager machineScopeManager) *cobra.Command {
	var checkOnly bool
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "setup-machine-scope",
		Short: "Prepare the machine-wide connectivity safety namespace",
		Long: "Prepare and validate the fixed machine-wide governor namespace. " +
			"This command never starts a WinkYou runtime or performs network activity.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var (
				status governor.NamespaceStatus
				err    error
				action = "setup"
			)
			if checkOnly {
				action = "check"
				status = manager.Inspect()
				if !status.Ready {
					err = fmt.Errorf("%w: state=%s detail=%s", governor.ErrNamespaceNotReady, status.State, status.Detail)
				}
			} else {
				status, err = manager.Setup()
			}

			if outputErr := writeMachineScopeStatus(cmd, status, asJSON); outputErr != nil {
				return outputErr
			}
			if err != nil {
				return fmt.Errorf("%s machine scope: %w", action, err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "validate the namespace without changing the machine")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output status as json")
	return cmd
}

func writeMachineScopeStatus(cmd *cobra.Command, status governor.NamespaceStatus, asJSON bool) error {
	if asJSON {
		return writeJSON(cmd, status)
	}
	cmd.Printf("Machine scope: %s\n", status.State)
	cmd.Printf("Path:          %s\n", dashIfEmpty(status.Path))
	if status.Detail != "" {
		cmd.Printf("Detail:        %s\n", status.Detail)
	}
	if status.State == governor.NamespaceUnsafe {
		cmd.Println("Action:        administrator review required; setup will not repair or adopt this path")
	} else if status.RequiresElevation {
		cmd.Println("Action:        run this command once from an elevated terminal")
	}
	cmd.Println("No WinkYou runtime or network activity was started.")
	return nil
}
