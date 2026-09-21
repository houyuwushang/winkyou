//go:build fieldc1c

package gateb

import (
	"winkyou/internal/probeio"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/oobcarrier"
)

type deploymentAuthority struct{ factory *probeio.FieldUDPFactory }

func (authority deploymentAuthority) present() bool { return authority.factory != nil }

// ConfigureFieldAttempt is callable only by the sealed field orchestrator.
// No ordinary command or injected Factory can select this private arm.
func ConfigureFieldAttempt(config *Config, instance fieldc1c.Instance, factory *probeio.FieldUDPFactory) error {
	if config == nil || config.deployment.present() || factory == nil {
		return oobcarrier.ErrInvalidConfig
	}
	binding, err := instance.Binding()
	if err != nil || config.PreparedArtifact == nil || binding.ID != config.PreparedArtifact.GateBAttemptID() ||
		binding.Role != string(config.PreparedArtifact.GateBLocalRole()) {
		return oobcarrier.ErrInvalidConfig
	}
	authority := deploymentAuthority{factory: factory}
	if err := authority.validate(*config); err != nil {
		return err
	}
	config.deployment = authority
	return nil
}

func (authority deploymentAuthority) validate(config Config) error {
	if !authority.present() {
		return nil
	}
	if config.ProbeFactory != nil || config.NATLabFactory != nil || config.HardNATLabFactory != nil ||
		config.Harness != nil || config.PreparedArtifact == nil || config.PreparedArtifact.GateBArtifactKind() != ArtifactKindGateC {
		return oobcarrier.ErrInvalidConfig
	}
	endpoints, err := config.ObserverTopology.Endpoints()
	if err != nil {
		return err
	}
	return authority.factory.Check(string(config.PreparedArtifact.GateBPlannerProfile()), string(config.PreparedArtifact.GateBResourceClass()),
		config.PreparedArtifact.GateBAttemptID(), config.ExpectedPeerAddress, endpoints)
}

func (runtime *runtime) deploymentFactory() (probeio.Factory, error) {
	if !runtime.product || runtime.config.deployment.validate(runtime.config) != nil {
		return nil, oobcarrier.ErrInvalidConfig
	}
	factory := runtime.config.deployment.factory
	if err := factory.BindAttempt(runtime.attempt); err != nil {
		return nil, err
	}
	return factory, nil
}

func (runtime *runtime) authorizeDeploymentPlan() error {
	if !runtime.config.deployment.present() {
		return nil
	}
	return runtime.config.deployment.factory.AuthorizePlan(runtime.localPlan)
}
