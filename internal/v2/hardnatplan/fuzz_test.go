package hardnatplan

import "testing"

func FuzzRFC5780CodecHardening(f *testing.F) {
	transaction := syntheticTransaction()
	request, _ := BuildBehaviorBindingRequest(transaction, ChangeRequest{ChangeIP: true, ChangePort: true})
	response, _ := BuildBehaviorBindingSuccess(transaction, BehaviorAttributes{
		Mapped:         AddressPort{Address: syntheticAddress(100).Address(), Port: 50000},
		ResponseOrigin: AddressPort{Address: syntheticAddress(10).Address(), Port: 3478},
		OtherAddress:   AddressPort{Address: syntheticAddress(11).Address(), Port: 3479},
		HasMapped:      true, HasResponseOrigin: true, HasOtherAddress: true,
	})
	f.Add(request)
	f.Add(response)
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _, _ = ParseBehaviorBindingRequest(payload)
		_, _ = ParseBehaviorBindingSuccess(payload, transaction)
	})
}

func FuzzRoleSeparatedPRPRemainsPermutation(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef"), "initiator")
	f.Add([]byte("fedcba9876543210fedcba9876543210"), "responder")
	f.Fuzz(func(t *testing.T, seed []byte, domain string) {
		if len(seed) != 32 || len(domain) > 64 {
			return
		}
		var key [32]byte
		copy(key[:], seed)
		values := portRange(49152, 50175)
		shuffleUint16(key, domain, values)
		seen := make(map[uint16]struct{}, len(values))
		for _, value := range values {
			if value == 0 {
				t.Fatal("PRP produced port zero")
			}
			if _, duplicate := seen[value]; duplicate {
				t.Fatalf("PRP duplicated %d", value)
			}
			seen[value] = struct{}{}
		}
	})
}
