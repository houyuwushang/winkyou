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
	if leftDraws > math.MaxUint64-rightDraws {
		return result, ErrProbabilityInputOverflow
	}
	if leftDraws+rightDraws > universe {
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
	result.LowerDecimal = successLower.Text('f', probabilityDecimalDigits)
	result.UpperDecimal = successUpper.Text('f', probabilityDecimalDigits)
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
// 1-exp(-(left*right)/universe) without float64. The exponential is a fixed
// 192-term rational series, making the cross-language golden deterministic.
func PoissonApproximation(universe, leftDraws, rightDraws uint64) (string, error) {
	if universe == 0 {
		return "", ErrInvalidProbabilityInput
	}
	product := new(big.Int).Mul(new(big.Int).SetUint64(leftDraws), new(big.Int).SetUint64(rightDraws))
	x := new(big.Rat).SetFrac(product, new(big.Int).SetUint64(universe))
	negativeX := new(big.Rat).Neg(new(big.Rat).Set(x))
	term := new(big.Rat).SetInt64(1)
	sum := new(big.Rat).SetInt64(1)
	for index := int64(1); index <= poissonSeriesTerms; index++ {
		term.Mul(term, negativeX)
		term.Quo(term, new(big.Rat).SetInt64(index))
		sum.Add(sum, term)
	}
	probability := new(big.Rat).Sub(new(big.Rat).SetInt64(1), sum)
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

func zeroDigits(count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = '0'
	}
	return string(result)
}
