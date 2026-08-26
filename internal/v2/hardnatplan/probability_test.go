package hardnatplan

import (
	"errors"
	"math/big"
	"testing"
)

func TestWithoutReplacementProbabilityExactSmallAndBoundaries(t *testing.T) {
	probability, err := CollisionProbabilityWithoutReplacement(10, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if probability.ExactRational != "8/15" || probability.FloorPartsPerTrillion != 533_333_333_333 {
		t.Fatalf("small exact probability = %+v", probability)
	}

	zero, err := CollisionProbabilityWithoutReplacement(65535, 0, 65535)
	if err != nil || zero.ExactRational != "0" || zero.FloorPartsPerTrillion != 0 {
		t.Fatalf("zero boundary = %+v/%v", zero, err)
	}
	one, err := CollisionProbabilityWithoutReplacement(1, 1, 1)
	if err != nil || one.ExactRational != "1" || one.FloorPartsPerTrillion != ProbabilityScale {
		t.Fatalf("one boundary = %+v/%v", one, err)
	}
	full, err := CollisionProbabilityWithoutReplacement(65535, 65535, 1)
	if err != nil || full.FloorPartsPerTrillion != ProbabilityScale {
		t.Fatalf("65535 boundary = %+v/%v", full, err)
	}
	if _, err := CollisionProbabilityWithoutReplacement(0, 0, 0); !errors.Is(err, ErrInvalidProbabilityInput) {
		t.Fatalf("zero universe error = %v", err)
	}
	if _, err := CollisionProbabilityWithoutReplacement(10, 11, 1); !errors.Is(err, ErrInvalidProbabilityInput) {
		t.Fatalf("overdraw error = %v", err)
	}
	forced, err := CollisionProbabilityWithoutReplacement(^uint64(0), ^uint64(0), 1)
	if err != nil || forced.ExactRational != "1" || forced.FloorPartsPerTrillion != ProbabilityScale {
		t.Fatalf("forced-intersection overflow boundary = %+v/%v", forced, err)
	}
}

func TestSerializedProbabilityIntervalContainsExactValue(t *testing.T) {
	probability, err := CollisionProbabilityWithoutReplacement(65535, 128, 512)
	if err != nil {
		t.Fatal(err)
	}
	exact, ok := new(big.Rat).SetString(probability.ExactRational)
	if !ok {
		t.Fatalf("invalid exact rational %q", probability.ExactRational)
	}
	lower, ok := new(big.Rat).SetString(probability.LowerDecimal)
	if !ok {
		t.Fatalf("invalid lower decimal %q", probability.LowerDecimal)
	}
	upper, ok := new(big.Rat).SetString(probability.UpperDecimal)
	if !ok {
		t.Fatalf("invalid upper decimal %q", probability.UpperDecimal)
	}
	if lower.Cmp(exact) > 0 || upper.Cmp(exact) < 0 {
		t.Fatalf("serialized interval [%s,%s] does not contain exact %s", lower, upper, exact)
	}
}

func TestPoissonApproximationRemainsBoundedForLargeExponent(t *testing.T) {
	for _, input := range [][3]uint64{{1000, 1000, 1000}, {^uint64(0), ^uint64(0), ^uint64(0)}, {65535, 0, 65535}} {
		approximation, err := PoissonApproximation(input[0], input[1], input[2])
		if err != nil {
			t.Fatal(err)
		}
		value, ok := new(big.Rat).SetString(approximation)
		if !ok || value.Sign() < 0 || value.Cmp(new(big.Rat).SetInt64(1)) > 0 {
			t.Fatalf("input %v approximation = %q", input, approximation)
		}
	}
}

func TestCheckedProductStillRejectsActualOverflow(t *testing.T) {
	if _, err := checkedProduct(^uint64(0), 2); !errors.Is(err, ErrProbabilityInputOverflow) {
		t.Fatalf("product overflow error = %v", err)
	}
}

func TestWithoutReplacementProbabilityIsSymmetricAndMonotonic(t *testing.T) {
	previous := uint64(0)
	for draws := uint64(1); draws <= 128; draws++ {
		left, err := CollisionProbabilityWithoutReplacement(65535, draws, 512)
		if err != nil {
			t.Fatal(err)
		}
		right, err := CollisionProbabilityWithoutReplacement(65535, 512, draws)
		if err != nil {
			t.Fatal(err)
		}
		if left.LowerDecimal != right.LowerDecimal || left.UpperDecimal != right.UpperDecimal {
			t.Fatalf("probability not symmetric at %d: %+v/%+v", draws, left, right)
		}
		if left.FloorPartsPerTrillion < previous {
			t.Fatalf("probability decreased at %d: %d < %d", draws, left.FloorPartsPerTrillion, previous)
		}
		previous = left.FloorPartsPerTrillion
	}
}

func FuzzWithoutReplacementProbabilityBoundaries(f *testing.F) {
	for _, seed := range [][3]uint64{{1, 1, 1}, {10, 2, 3}, {65535, 128, 512}, {65535, 0, 1}} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, universe, left, right uint64) {
		if universe == 0 || universe > 1_000_000 || left > universe || right > universe {
			return
		}
		probability, err := CollisionProbabilityWithoutReplacement(universe, left, right)
		if err != nil {
			if errors.Is(err, ErrProbabilityInputOverflow) {
				return
			}
			t.Fatal(err)
		}
		if probability.FloorPartsPerTrillion > ProbabilityScale || probability.LowerDecimal > probability.UpperDecimal {
			t.Fatalf("invalid probability interval: %+v", probability)
		}
	})
}
