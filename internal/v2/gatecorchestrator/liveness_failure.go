package gatecorchestrator

import "errors"

func livenessFailure(input preparedInput, cause error, running bool) *Failure {
	class := errLivenessUnavailable.Error()
	for _, candidate := range []error{errLivenessTimeout, errLivenessProtocol, errLivenessClock, errLivenessBudget, errLivenessUnavailable} {
		if errors.Is(cause, candidate) {
			class = candidate.Error()
			break
		}
	}
	stage := StagePreflight
	if running {
		stage = StageTerminal
	}
	return &Failure{Class: class, Stage: stage, CredentialBurned: running, FinishRecorded: &running,
		Retryable: false, Profile: profileOf(input), ResourceClass: resourceOf(input), Cause: cause}
}
