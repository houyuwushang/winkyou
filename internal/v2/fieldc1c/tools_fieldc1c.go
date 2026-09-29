//go:build fieldc1c

package fieldc1c

import (
	"runtime/debug"
	"sort"
	"strings"
)

// DependencyConfigurationDigest reuses the exact Load/LoadRouter digest. It
// issues no authorization and accepts no local path or executable capability.
func DependencyConfigurationDigest(info *debug.BuildInfo, configuration [2]string) (string, error) {
	if info == nil || !hexValue(configuration[0], 32) || !hexValue(configuration[1], 32) {
		return "", ErrInvalid
	}
	var dependencies []string
	seen := make(map[string]bool)
	for _, dependency := range info.Deps {
		if dependency == nil || dependency.Replace != nil || dependency.Path == "" || seen[dependency.Path] ||
			strings.ContainsRune(dependency.Path+dependency.Version+dependency.Sum, 0) {
			return "", ErrInvalid
		}
		seen[dependency.Path] = true
		dependencies = append(dependencies, dependency.Path+"\x00"+dependency.Version+"\x00"+dependency.Sum)
	}
	sort.Strings(dependencies)
	return dependencyDigest(buildWitness{dependencies: dependencies}, []Device{
		{Role: "initiator", ConfigurationSHA256: configuration[0]},
		{Role: "responder", ConfigurationSHA256: configuration[1]},
	}), nil
}

// MachineScopeReference is a read-only projection of the current mount view;
// it uses the same implementation as Load and cannot select another scope.
func MachineScopeReference() (string, error) { return localMachineReference() }
