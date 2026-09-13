package hardnatplan

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestAsymmetricProbabilityCacheMatchesFreshMathAndOwnsValues(t *testing.T) {
	fresh, err := computeAsymmetricProbabilityNumbers()
	if err != nil {
		t.Fatal(err)
	}
	const calls = 64
	var workers sync.WaitGroup
	for index := 0; index < calls; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			cached, err := frozenAsymmetricNumbers()
			if err != nil || cached != fresh {
				t.Error("cached numbers differ from independent exact recomputation")
				return
			}
			// There are no mutable pointers, slices or maps in cached numbers.
			cached.primary.LowerDecimal = "local mutation"
			cached.primary.FloorPartsPerTrillion = 0
			cached.poisson, cached.delta = "local mutation", "local mutation"
			role := RoleMappingSet
			if index%2 == 1 {
				role = RoleTargetSet
			}
			shape, err := shapeFor(ProfileAsymmetricBirthday, ResourceAsymmetric, role, StateModel{})
			if err != nil {
				t.Error(err)
				return
			}
			coverage := fmt.Sprintf("synthetic caller %d", index)
			report, err := probabilityFor(ProfileAsymmetricBirthday, ResourceAsymmetric, StateModel{Coverage: coverage}, shape)
			if err != nil || report.Primary != fresh.primary || report.FullRangeBaseline != fresh.primary ||
				report.PoissonApproximation != fresh.poisson || report.ApproximationDelta != fresh.delta ||
				report.ModelCoverage != coverage || !report.Conditional || report.Model != string(ProfileAsymmetricBirthday) {
				t.Error("numeric reuse changed per-call coverage/model or mathematical output")
			}
		}(index)
	}
	workers.Wait()
	var valueOnly func(reflect.Type) bool
	valueOnly = func(kind reflect.Type) bool {
		switch kind.Kind() {
		case reflect.Bool, reflect.String, reflect.Uint, reflect.Uint64:
			return true
		case reflect.Struct:
			for index := 0; index < kind.NumField(); index++ {
				if !valueOnly(kind.Field(index).Type) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	if !valueOnly(reflect.TypeOf(fresh)) {
		t.Fatal("shared probability acquired mutable aliasing state")
	}
}

func TestAsymmetricCachedNumbersDoNotBypassCommitmentValidation(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	commitment, err := BuildLocalCommitment(localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleMappingSet, graph))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*LocalSourceCommitment){
		func(c *LocalSourceCommitment) { c.Cost.Packets++ },
		func(c *LocalSourceCommitment) { c.Probability.Primary.FloorPartsPerTrillion++ },
		func(c *LocalSourceCommitment) { c.Probability.Primary.UpperDecimal = "1" },
		func(c *LocalSourceCommitment) { c.Probability.ModelCoverage = "foreign coverage" },
		func(c *LocalSourceCommitment) { c.SourceDigest[0] ^= 1 },
		func(c *LocalSourceCommitment) { c.EvidenceDigest[0] ^= 1 },
		func(c *LocalSourceCommitment) { c.ValidationDigest[0] ^= 1 },
	} {
		changed := commitment.Clone()
		mutate(&changed)
		if err := validateLocalCommitment(changed); !errors.Is(err, ErrPlanMismatch) {
			t.Fatalf("cached mathematics accepted changed commitment: %v", err)
		}
	}
}

func TestAsymmetricProbabilityCacheHasOneConstantEntry(t *testing.T) {
	// A performance regression guard independent of runner speed. Cache only
	// compiled mathematical constants, never caller-controlled identity/data.
	source, err := os.ReadFile("planner.go")
	if err != nil {
		t.Fatal(err)
	}
	check := func(source string) bool {
		return strings.Contains(source, "var frozenAsymmetricNumbers = sync.OnceValues(computeAsymmetricProbabilityNumbers)") &&
			strings.Count(source, "numbers, err := frozenAsymmetricNumbers()") == 1
	}
	if !check(string(source)) || check(strings.ReplaceAll(string(source), "sync.OnceValues(computeAsymmetricProbabilityNumbers)", "computeAsymmetricProbabilityNumbers")) ||
		check(strings.ReplaceAll(string(source), "numbers, err := frozenAsymmetricNumbers()", "numbers, err := computeAsymmetricProbabilityNumbers()")) {
		t.Fatal("repeated high-precision arithmetic mutation was not rejected")
	}
}

var probabilityCacheBenchmarkSink asymmetricProbabilityNumbers

func BenchmarkAsymmetricProbabilityNumbersFresh(b *testing.B) {
	for index := 0; index < b.N; index++ {
		value, err := computeAsymmetricProbabilityNumbers()
		if err != nil {
			b.Fatal(err)
		}
		probabilityCacheBenchmarkSink = value
	}
}

func BenchmarkAsymmetricProbabilityNumbersCached(b *testing.B) {
	if _, err := frozenAsymmetricNumbers(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		value, err := frozenAsymmetricNumbers()
		if err != nil {
			b.Fatal(err)
		}
		probabilityCacheBenchmarkSink = value
	}
}
