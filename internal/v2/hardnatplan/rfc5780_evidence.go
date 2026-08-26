package hardnatplan

type derivedRFC5780Transcript struct {
	observations [RFC5780ExchangeCount]DiscoveryObservation
	mapping      MappingBehavior
	filtering    FilteringBehavior
	endpoint     AddressPort
}

var orderedRFC5780Steps = [RFC5780ExchangeCount]DiscoveryStep{
	StepPrimary,
	StepSameAddressOtherPort,
	StepOtherAddress,
	StepChangeIPPort,
	StepChangePort,
}

func deriveRFC5780Transcript(transcript RFC5780Transcript) (derivedRFC5780Transcript, error) {
	var derived derivedRFC5780Transcript
	machine := NewRFC5780Machine()
	for index, exchange := range transcript.Exchanges {
		step := orderedRFC5780Steps[index]
		if exchange.Step != step || exchange.ObservedAtMilli <= 0 || !exchange.RequestDestination.Valid() {
			return derived, ErrInvalidEvidence
		}
		transaction, change, err := ParseBehaviorBindingRequest(exchange.Request)
		if err != nil || transaction != exchange.TransactionID || change != expectedRFC5780Change(step) {
			return derived, ErrInvalidEvidence
		}
		observation := DiscoveryObservation{
			TransactionID: exchange.TransactionID, RequestDestination: exchange.RequestDestination,
			ResponseSource: exchange.ResponseSource, Received: exchange.Received,
		}
		if exchange.Received {
			if len(exchange.Response) == 0 || !exchange.ResponseSource.Valid() {
				return derived, ErrInvalidEvidence
			}
			attributes, parseErr := ParseBehaviorBindingSuccess(exchange.Response, exchange.TransactionID)
			if parseErr != nil {
				return derived, parseErr
			}
			observation.Attributes = attributes
		} else if len(exchange.Response) != 0 || exchange.ResponseSource != (AddressPort{}) {
			return derived, ErrInvalidEvidence
		}
		machine, err = machine.Advance(step, observation)
		if err != nil {
			return derived, err
		}
		derived.observations[index] = observation
	}
	mapping, filtering, err := machine.Result()
	if err != nil {
		return derivedRFC5780Transcript{}, err
	}
	derived.mapping, derived.filtering = mapping, filtering
	if mapping == MappingEIM {
		derived.endpoint = derived.observations[0].Attributes.Mapped
	}
	return derived, nil
}

func expectedRFC5780Change(step DiscoveryStep) ChangeRequest {
	switch step {
	case StepChangeIPPort:
		return ChangeRequest{ChangeIP: true, ChangePort: true}
	case StepChangePort:
		return ChangeRequest{ChangePort: true}
	default:
		return ChangeRequest{}
	}
}

func reusableRFC5780Endpoint(transcripts []RFC5780Transcript) (AddressPort, uint16, error) {
	var endpoint AddressPort
	var socketSlot uint16
	for _, transcript := range transcripts {
		derived, err := deriveRFC5780Transcript(transcript)
		if err != nil {
			return AddressPort{}, 0, err
		}
		if derived.mapping != MappingEIM {
			continue
		}
		if !derived.endpoint.Valid() {
			return AddressPort{}, 0, ErrInvalidEvidence
		}
		if endpoint.Valid() && (endpoint != derived.endpoint || socketSlot != transcript.SocketSlot) {
			return AddressPort{}, 0, ErrEvidenceInsufficient
		}
		endpoint, socketSlot = derived.endpoint, transcript.SocketSlot
	}
	return endpoint, socketSlot, nil
}
