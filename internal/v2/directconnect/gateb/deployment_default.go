//go:build !fieldc1c

package gateb

import "winkyou/internal/probeio"

type deploymentAuthority struct{}

func (deploymentAuthority) present() bool                            { return false }
func (deploymentAuthority) validate(Config) error                    { return nil }
func (runtime *runtime) deploymentFactory() (probeio.Factory, error) { return nil, nil }
func (runtime *runtime) authorizeDeploymentPlan() error              { return nil }
