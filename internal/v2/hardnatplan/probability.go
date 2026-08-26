package hardnatplan

import (
	"fmt"
	"math"
	"math/big"
)

const (
	probabilityDecimalDigits = 50
	exactRationalDrawLimit   = uint64(4096)
	poissonSeriesTerms       = 192
	poissonSaturation        = int64(128)
)

// Probability is a directed-rounding interval for the exact
// without-replacement collision probability. FloorPartsPerTrillion is derived
// only from LowerDecimal's internal lower bound and is therefore safe for
// admission; the upper bound is diagnostic only.
type Probability struct {
	Universe              uint64 `json:"universe"`
	LeftDraws             uint64 `json:"left_draws"`
	RightDraws            uint64 `json:"right_draws"`
	PrecisionBits         uint   `json:"precision_bits"`
	LowerDecimal          string `json:"lower_decimal"`
	UpperDecimal          string `json:"upper_decimal"`
	FloorPartsPerTrillion uint64 `json:"floor_parts_per_trillion"`
	ExactRational         string `json:"exact_rational,omitempty"`
}

// CollisionProbabilityWithoutReplacement calculates the probability that two
// independently selected subsets intersect. Each subset has no replacement;
// the two subsets are selected from the same universe.
func CollisionProbabilityWithoutReplacement(universe, leftDraws, rightDraws uint64) (Probability, error) {
	result := Probability{
		Universe:      universe,
		LeftDraws:     leftDraws,
		RightDraws:    rightDraws,
		PrecisionBits: ProbabilityPrecisionBits,
	}
	if universe == 0 || leftDraws > universe || rightDraws > universe {
		return result, ErrInvalidProbabilityInput
	}
	if leftDraws == 0 || rightDraws == 0 {
		return exactBoundaryProbability(result, false), nil
	}
	// Both draws were already proved <= universe. This subtraction form
	// detects a forced intersection without overflowing at MaxUint64.
	if leftDraws > universe-rightDraws {
		return exactBoundaryProbability(result, true), nil
	}

	// Symmetry allows the shorter product without changing the probability.
	blocked, draws := leftDraws, rightDraws
	if draws > blocked {
		blocked, draws = draws, blocked
	}
	missLower := probabilityFloat(big.ToNegativeInf).SetInt64(1)
	missUpper := probabilityFloat(big.ToPositiveInf).SetInt64(1)
	for ordinal := uint64(0); ordinal < draws; ordinal++ {
		numerator := universe - blocked - ordinal
		denominator := universe - ordinal
		lowerRatio := probabilityFloat(big.ToNegativeInf).Quo(
			probabilityFloat(big.ToNegativeInf).SetUint64(numerator),
			probabilityFloat(big.ToPositiveInf).SetUint64(denominator),
		)
		upperRatio := probabilityFloat(big.ToPositiveInf).Quo(
			probabilityFloat(big.ToPositiveInf).SetUint64(numerator),
			probabilityFloat(big.ToNegativeInf).SetUint64(denominator),
		)
		missLower.Mul(missLower, lowerRatio)
		missUpper.Mul(missUpper, upperRatio)
	}
	oneLower := probabilityFloat(big.ToNegativeInf).SetInt64(1)
	oneUpper := probabilityFloat(big.ToPositiveInf).SetInt64(1)
	successLower := probabilityFloat(big.ToNegativeInf).Sub(oneLower, missUpper)
	successUpper := probabilityFloat(big.ToPositiveInf).Sub(oneUpper, missLower)
	if successLower.Sign() < 0 {
		successLower.SetInt64(0)
	}
	if successUpper.Cmp(probabilityFloat(big.ToPositiveInf).SetInt64(1)) > 0 {
		successUpper.SetInt64(1)
	}
	result.LowerDecimal = directedDecimal(successLower, probabilityDecimalDigits, false)
	result.UpperDecimal = directedDecimal(successUpper, probabilityDecimalDigits, true)
	result.FloorPartsPerTrillion = floorScaled(successLower, ProbabilityScale)
	if draws <= exactRationalDrawLimit {
		result.ExactRational = exactCollisionRational(universe, blocked, draws).RatString()
	}
	return result, nil
}

func exactBoundaryProbability(result Probability, one bool) Probability {
	value := "0"
	decimal := "0." + zeroDigits(probabilityDecimalDigits)
	if one {
		value = "1"
		decimal = "1." + zeroDigits(probabilityDecimalDigits)
		result.FloorPartsPerTrillion = ProbabilityScale
	}
	result.LowerDecimal = decimal
	result.UpperDecimal = decimal
	result.ExactRational = value
	return result
}

func probabilityFloat(mode big.RoundingMode) *big.Float {
	return new(big.Float).SetPrec(ProbabilityPrecisionBits).SetMode(mode)
}

func floorScaled(value *big.Float, scale uint64) uint64 {
	if value == nil || value.Sign() <= 0 {
		return 0
	}
	scaled := probabilityFloat(big.ToNegativeInf).Mul(value, probabilityFloat(big.ToNegativeInf).SetUint64(scale))
	integer, _ := scaled.Int(nil)
	if integer.Sign() <= 0 {
		return 0
	}
	if !integer.IsUint64() {
		return scale
	}
	result := integer.Uint64()
	if result > scale {
		return scale
	}
	return result
}

func exactCollisionRational(universe, blocked, draws uint64) *big.Rat {
	miss := new(big.Rat).SetInt64(1)
	for ordinal := uint64(0); ordinal < draws; ordinal++ {
		ratio := new(big.Rat).SetFrac(
			new(big.Int).SetUint64(universe-blocked-ordinal),
			new(big.Int).SetUint64(universe-ordinal),
		)
		miss.Mul(miss, ratio)
	}
	return new(big.Rat).Sub(new(big.Rat).SetInt64(1), miss)
}

// PoissonApproximation returns the ADR's uniform approximation
// 1-exp(-(left*right)/universe) without float64. Range reduction keeps the
// positive rational series bounded; repeated squaring reconstructs exp(-x).
func PoissonApproximation(universe, leftDraws, rightDraws uint64) (string, error) {
	if universe == 0 {
		return "", ErrInvalidProbabilityInput
	}
	product := new(big.Int).Mul(new(big.Int).SetUint64(leftDraws), new(big.Int).SetUint64(rightDraws))
	x := new(big.Rat).SetFrac(product, new(big.Int).SetUint64(universe))
	if x.Sign() == 0 {
		return new(big.Rat).FloatString(probabilityDecimalDigits), nil
	}
	if x.Cmp(new(big.Rat).SetInt64(poissonSaturation)) >= 0 {
		return new(big.Rat).SetInt64(1).FloatString(probabilityDecimalDigits), nil
	}

	reduced := new(big.Rat).Set(x)
	oneEighth := new(big.Rat).SetFrac64(1, 8)
	reductions := 0
	for reduced.Cmp(oneEighth) > 0 {
		reduced.Quo(reduced, new(big.Rat).SetInt64(2))
		reductions++
	}
	// Compute exp(reduced) with positive terms, then invert. This avoids the
	// catastrophic cancellation of a direct alternating exp(-x) series.
	term := new(big.Rat).SetInt64(1)
	sum := new(big.Rat).SetInt64(1)
	for index := int64(1); index <= poissonSeriesTerms; index++ {
		term.Mul(term, reduced)
		term.Quo(term, new(big.Rat).SetInt64(index))
		sum.Add(sum, term)
	}
	miss := new(big.Rat).Inv(sum)
	for index := 0; index < reductions; index++ {
		miss.Mul(miss, miss)
	}
	probability := new(big.Rat).Sub(new(big.Rat).SetInt64(1), miss)
	if probability.Sign() < 0 {
		probability.SetInt64(0)
	} else if probability.Cmp(new(big.Rat).SetInt64(1)) > 0 {
		probability.SetInt64(1)
	}
	return probability.FloatString(probabilityDecimalDigits), nil
}

// ApproximationDelta returns exact-lower minus the Poisson approximation. Its
// sign and order of magnitude are frozen in golden vectors; the lower endpoint
// keeps the value conservative.
func ApproximationDelta(probability Probability, approximation string) (string, error) {
	lower, _, err := big.ParseFloat(probability.LowerDecimal, 10, ProbabilityPrecisionBits, big.ToNegativeInf)
	if err != nil {
		return "", fmt.Errorf("%w: parse probability lower bound", ErrInvalidProbabilityInput)
	}
	approximate, _, err := big.ParseFloat(approximation, 10, ProbabilityPrecisionBits, big.ToNearestEven)
	if err != nil {
		return "", fmt.Errorf("%w: parse approximation", ErrInvalidProbabilityInput)
	}
	delta := probabilityFloat(big.ToNegativeInf).Sub(lower, approximate)
	return delta.Text('e', 20), nil
}

func checkedProduct(left, right uint64) (uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, ErrProbabilityInputOverflow
	}
	return left * right, nil
}

// directedDecimal converts a non-negative binary bound into a fixed-scale
// decimal bound without undoing its rounding direction. Lower endpoints use
// floor; upper endpoints use ceil.
func directedDecimal(value *big.Float, digits int, upper bool) string {
	if value == nil || value.Sign() <= 0 {
		return "0." + zeroDigits(digits)
	}
	rational, _ := value.Rat(nil)
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	scaledNumerator := new(big.Int).Mul(rational.Num(), scale)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(scaledNumerator, rational.Denom(), remainder)
	if upper && remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	integer, fraction := new(big.Int), new(big.Int)
	integer.QuoRem(quotient, scale, fraction)
	fractionText := fraction.String()
	if padding := digits - len(fractionText); padding > 0 {
		fractionText = zeroDigits(padding) + fractionText
	}
	return integer.String() + "." + fractionText
}

func zeroDigits(count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = '0'
	}
	return string(result)
}
