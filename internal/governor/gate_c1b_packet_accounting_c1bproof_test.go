//go:build c1bproof

package governor_test

import (
	"fmt"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

type gateC1bPacketProof struct {
	emissions     gateb.Emissions
	establishment int
	active        int
	actualUDP     uint64
}

// Cross-check the independent NAT counter against bounded protocol components,
// never against the historical OS fixture's candidate/winner schedule. The
// FINISH snapshots additionally prove zero emission during the injected wait.
func validateGateC1bPacketAccounting(profile gateC1bMemoryProfile, packets [2]gateC1bPacketProof, delay *governor.C1bFinishDelayProof) error {
	envelope, err := hardnatbudget.For(profile.profile, profile.resource)
	if err != nil {
		return err
	}
	roles := [2]hardnatplan.Role{hardnatplan.RoleInitiator, hardnatplan.RoleResponder}
	var candidates [2]int
	switch profile.profile {
	case hardnatplan.ProfilePredictiveEdm:
		candidates = [2]int{hardnatplan.PredictiveWindowPorts, hardnatplan.PredictiveWindowPorts}
	case hardnatplan.ProfileAsymmetricBirthday:
		roles = [2]hardnatplan.Role{hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet}
		candidates = [2]int{128, 512} // frozen asymmetric role budgets, not OS totals
	case hardnatplan.ProfileHardBirthday:
		candidates = [2]int{hardnatbudget.Hard16CandidatePackets, hardnatbudget.Hard16CandidatePackets}
	default:
		return fmt.Errorf("unknown memory accounting profile")
	}
	if profile.plannerRoles != roles {
		return fmt.Errorf("memory accounting role/profile mismatch")
	}
	if delay != nil && (delay.Calls != 1 || delay.Waited < 3500*time.Millisecond) {
		return fmt.Errorf("memory FINISH delay did not observe exactly one complete wait")
	}
	winners := 0
	for side, packet := range packets {
		e := packet.emissions
		if e.EvidencePackets != hardnatbudget.FreshEvidencePackets ||
			e.CandidatePackets < 1 || e.CandidatePackets > candidates[side] ||
			e.WinnerPackets < 0 || e.WinnerPackets > 1 ||
			e.DataPacketsWritten != 0 || e.DataPacketsRead != 0 {
			return fmt.Errorf("side %d memory evidence/candidate/winner allowance mismatch", side)
		}
		complete := profile.profile == hardnatplan.ProfileHardBirthday || roles[side] == hardnatplan.RoleTargetSet
		if complete && e.CandidatePackets != candidates[side] {
			return fmt.Errorf("side %d memory full schedule incomplete", side)
		}
		// All addends were individually bounded above before this arithmetic.
		probePackets := e.EvidencePackets + e.CandidatePackets + e.WinnerPackets
		if e.UDPPacketsTotal != probePackets || probePackets > envelope.Cost.Resources.Packets {
			return fmt.Errorf("side %d memory probe sum/budget mismatch", side)
		}
		wantActive := [2]int{2, 1}[side] // echo request+CLOSE / echo reply
		if packet.establishment != 3 || packet.active != wantActive {
			return fmt.Errorf("side %d memory establishment/data allowance mismatch", side)
		}
		beforeActive := uint64(probePackets + packet.establishment)
		if packet.actualUDP != beforeActive+uint64(wantActive) {
			return fmt.Errorf("side %d memory actual UDP differs from exact component sum", side)
		}
		if delay != nil && (delay.Before[side] != beforeActive || delay.After[side] != delay.Before[side]) {
			return fmt.Errorf("side %d emitted during or outside the FINISH completion boundary", side)
		}
		winners += e.WinnerPackets
	}
	if winners != 1 {
		return fmt.Errorf("memory successful pair did not emit exactly one winner")
	}
	return nil
}

type gateC1bAccountingFixture struct {
	profile gateC1bMemoryProfile
	packets [2]gateC1bPacketProof
	delay   governor.C1bFinishDelayProof
}

func gateC1bAccountingExample(index int) gateC1bAccountingFixture {
	fixture := gateC1bAccountingFixture{profile: gateC1bMemoryProfiles[index],
		delay: governor.C1bFinishDelayProof{Calls: 1, Waited: 3500 * time.Millisecond}}
	candidates := [][2]int{{32, 32}, {128, 512}, {16384, 16384}}[index]
	winners := [][2]int{{1, 0}, {0, 1}, {0, 1}}[index]
	for side := range 2 {
		probePackets := 13 + candidates[side] + winners[side]
		fixture.packets[side] = gateC1bPacketProof{
			emissions: gateb.Emissions{EvidencePackets: 13, CandidatePackets: candidates[side],
				WinnerPackets: winners[side], UDPPacketsTotal: probePackets},
			establishment: 3, active: [2]int{2, 1}[side],
			actualUDP: uint64(probePackets + 3 + [2]int{2, 1}[side]),
		}
		fixture.delay.Before[side], fixture.delay.After[side] = uint64(probePackets+3), uint64(probePackets+3)
	}
	return fixture
}

// This is a child of the existing required entry, not an unselected optional
// test. Mutations are pure proof-data changes; they emit no packet at all.
func testGateC1bPacketAccountingOracle(t *testing.T) {
	for index := range gateC1bMemoryProfiles {
		fixture := gateC1bAccountingExample(index)
		t.Run(fixture.profile.name, func(t *testing.T) {
			if err := validateGateC1bPacketAccounting(fixture.profile, fixture.packets, &fixture.delay); err != nil {
				t.Fatal(err)
			}
		})
	}
	mutations := []struct {
		name string
		edit func(*gateC1bAccountingFixture)
	}{
		{"extra_udp_i", func(f *gateC1bAccountingFixture) { f.packets[0].actualUDP++ }},
		{"extra_udp_r", func(f *gateC1bAccountingFixture) { f.packets[1].actualUDP++ }},
		{"wait_emission_i", func(f *gateC1bAccountingFixture) { f.delay.After[0]++ }},
		{"wait_emission_r", func(f *gateC1bAccountingFixture) { f.delay.After[1]++ }},
		{"wrong_wait_boundary", func(f *gateC1bAccountingFixture) { f.delay.Before[0]++; f.delay.After[0]++ }},
		{"short_wait", func(f *gateC1bAccountingFixture) { f.delay.Waited = 3499 * time.Millisecond }},
		{"repeated_finish", func(f *gateC1bAccountingFixture) { f.delay.Calls = 2 }},
		{"missing_finish", func(f *gateC1bAccountingFixture) { f.delay.Calls = 0 }},
		{"fourth_establishment", func(f *gateC1bAccountingFixture) { f.packets[0].establishment = 4 }},
		{"extra_active", func(f *gateC1bAccountingFixture) { f.packets[0].active++ }},
		{"probe_total_mismatch", func(f *gateC1bAccountingFixture) { f.packets[0].emissions.UDPPacketsTotal++ }},
		{"unexpected_test_consumer", func(f *gateC1bAccountingFixture) { f.packets[0].emissions.DataPacketsWritten = 1 }},
		{"negative_candidate", func(f *gateC1bAccountingFixture) { f.packets[0].emissions.CandidatePackets = -1 }},
		{"role_mismatch", func(f *gateC1bAccountingFixture) { f.profile.plannerRoles[0] = hardnatplan.RoleTargetSet }},
		{"resource_mismatch", func(f *gateC1bAccountingFixture) { f.profile.resource = hardnatplan.ResourceAsymmetric }},
		{"self_consistent_over_budget", func(f *gateC1bAccountingFixture) {
			f.packets[0].emissions.CandidatePackets++
			f.packets[0].emissions.UDPPacketsTotal++
			f.packets[0].actualUDP++
			f.delay.Before[0]++
			f.delay.After[0]++
		}},
		{"self_consistent_extra_evidence", func(f *gateC1bAccountingFixture) {
			f.packets[0].emissions.EvidencePackets++
			f.packets[0].emissions.UDPPacketsTotal++
			f.packets[0].actualUDP++
			f.delay.Before[0]++
			f.delay.After[0]++
		}},
		{"two_winners", func(f *gateC1bAccountingFixture) {
			f.packets[1].emissions.WinnerPackets++
			f.packets[1].emissions.UDPPacketsTotal++
			f.packets[1].actualUDP++
			f.delay.Before[1]++
			f.delay.After[1]++
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := gateC1bAccountingExample(0)
			mutation.edit(&fixture)
			if validateGateC1bPacketAccounting(fixture.profile, fixture.packets, &fixture.delay) == nil {
				t.Fatal("invalid accounting proof accepted")
			}
		})
	}
	for _, index := range []int{1, 2} {
		t.Run("incomplete_full_schedule_"+gateC1bMemoryProfiles[index].name, func(t *testing.T) {
			fixture := gateC1bAccountingExample(index)
			fixture.packets[1].emissions.CandidatePackets--
			fixture.packets[1].emissions.UDPPacketsTotal--
			fixture.packets[1].actualUDP--
			fixture.delay.Before[1]--
			fixture.delay.After[1]--
			if validateGateC1bPacketAccounting(fixture.profile, fixture.packets, &fixture.delay) == nil {
				t.Fatal("incomplete full schedule accepted")
			}
		})
	}
}
