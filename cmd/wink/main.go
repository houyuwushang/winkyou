package main

import (
	"fmt"
	"os"

	"winkyou/cmd/wink/cmd"
)

func main() {
	if handled, err := dispatchDeploymentWrapper(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "gate_c_request_invalid")
			os.Exit(1)
		}
		return
	}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
