package hardnatbudget

import (
	"fmt"
	"testing"

	"winkyou/internal/governor"
	"winkyou/internal/v2/hardnatplan"
)

func TestFrozenExecutionEnvelopes(t *testing.T) {
	tests := []struct {
		profile  hardnatplan.Profile
		resource hardnatplan.ResourceClass
		op       governor.Operation
		want     governor.Resources
		wantHash string
	}{
		{hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, governor.OperationPrediction,
			governor.Resources{Sockets: 8, Targets: 64, FiveTuples: 64, Packets: 64, PacketsPerSecond: 32}, "4d4a2b8d8c26f878153b9edc90d70d906322de3f6f503da10de9061d47bc3c7d"},
		{hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, governor.OperationBirthday,
			governor.Resources{Sockets: 128, Targets: 516, FiveTuples: 523, Packets: 526, PacketsPerSecond: 64}, "aa62e575a98c007ce43d065bf5a1ad74a18d4e7f71ce4180b16bf1896eaa3e9d"},
		{hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab, governor.OperationBirthday,
			governor.Resources{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512}, "930a972a287334f3062448ce23b49c823675fd1457b5ab0e05bddc0a57cfa263"},
	}
	for _, test := range tests {
		envelope, err := For(test.profile, test.resource)
		wantDuration := AttemptDuration
		if test.resource == hardnatplan.ResourceHard16KLab {
			wantDuration = Hard16AttemptDuration
		}
		if err != nil || envelope.Cost.Resources != test.want || envelope.Cost.Duration != wantDuration || !envelope.Cost.Heavyweight {
			t.Fatalf("For(%s) = %+v, %v", test.profile, envelope, err)
		}
		if !Exact(test.profile, test.resource, test.op, envelope.Cost) {
			t.Fatalf("exact envelope rejected for %s", test.profile)
		}
		if digest, err := Digest(envelope); err != nil || digest == ([32]byte{}) || fmt.Sprintf("%x", digest) != test.wantHash {
			t.Fatalf("Digest(%s) = %x, %v; want %s", test.profile, digest, err, test.wantHash)
		}
	}
}

func TestEnvelopeCannotBorrowAcrossProfiles(t *testing.T) {
	predictive, _ := For(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
	asymmetric, _ := For(hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric)
	hard16, _ := For(hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab)
	if Exact(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, governor.OperationPrediction, asymmetric.Cost) ||
		Exact(hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, governor.OperationBirthday, predictive.Cost) ||
		Exact(hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab, governor.OperationBirthday, asymmetric.Cost) ||
		Exact(hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, governor.OperationBirthday, hard16.Cost) {
		t.Fatal("cross-profile envelope was accepted")
	}
	if profile, err := GovernorProfile(hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab); err != nil ||
		profile != governor.ProfilePhase1HardNATCampaign {
		t.Fatalf("hard16 governor profile = %q/%v", profile, err)
	}
}
