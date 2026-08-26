package hardnatplan

import (
	"errors"
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
	if _, err := CollisionProbabilityWithoutReplacement(^uint64(0), ^uint64(0), 1); !errors.Is(err, ErrProbabilityInputOverflow) {
		t.Fatalf("sum overflow error = %v", err)
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
