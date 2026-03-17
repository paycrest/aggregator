package utils

import (
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestUtils(t *testing.T) {

	t.Run("ToSubunit", func(t *testing.T) {
		testCases := []struct {
			amount    decimal.Decimal
			decimals  int8
			expectVal *big.Int
		}{
			{
				amount:    decimal.NewFromFloat(1.23),
				decimals:  2,
				expectVal: big.NewInt(123),
			},
			{
				amount:    decimal.NewFromFloat(0.001),
				decimals:  8,
				expectVal: big.NewInt(100000),
			},
			{
				amount:    decimal.NewFromFloat(0.005),
				decimals:  18,
				expectVal: big.NewInt(5000000000000000),
			},
		}

		for _, tc := range testCases {
			actualVal := ToSubunit(tc.amount, tc.decimals)
			assert.Equal(t, tc.expectVal, actualVal)
		}
	})

	t.Run("FromSubunit", func(t *testing.T) {
		testCases := []struct {
			amountInSubunit *big.Int
			decimals        int8
			expectVal       decimal.Decimal
		}{
			{
				amountInSubunit: big.NewInt(123),
				decimals:        2,
				expectVal:       decimal.NewFromFloat(1.23),
			},
			{
				amountInSubunit: big.NewInt(1),
				decimals:        8,
				expectVal:       decimal.NewFromFloat(0.00000001),
			},
			{
				amountInSubunit: big.NewInt(5000000000000000),
				decimals:        18,
				expectVal:       decimal.NewFromFloat(0.005),
			},
		}

		for _, tc := range testCases {
			actualVal := FromSubunit(tc.amountInSubunit, tc.decimals)
			assert.Equal(t, tc.expectVal, actualVal)
		}
	})

	t.Run("TestMedian", func(t *testing.T) {
		data := []decimal.Decimal{
			decimal.NewFromInt(9),
			decimal.NewFromInt(1),
			decimal.NewFromInt(5),
			decimal.NewFromInt(6),
			decimal.NewFromInt(2),
			decimal.NewFromInt(1),
			decimal.NewFromInt(3),
			decimal.NewFromInt(1),
			decimal.NewFromInt(1),
			decimal.NewFromInt(2),
		}

		median := Median(data)

		assert := assert.New(t)
		assert.True(median.Equal(decimal.NewFromInt(2)), "Median calculation is incorrect")
	})
}

func TestNormalizeMobileMoneyAccountIdentifier(t *testing.T) {
	tests := []struct {
		name              string
		currencyCode      string
		accountIdentifier string
		want              string
	}{
		// UGX (256)
		{"UGX with + and leading spaces", "UGX", "+ 256701234567", "256701234567"},
		{"UGX plus and dial code no internal space", "UGX", "+256701234567", "256701234567"},
		{"UGX local number gets prefix", "UGX", "701234567", "256701234567"},
		{"UGX already has dial code", "UGX", "256701234567", "256701234567"},
		{"UGX plus and dial code lowercase currency", "ugx", "+256701234567", "256701234567"},
		{"UGX leading non-digit then digits", "UGX", "+ x701234567", "256701234567"},
		// TZS (255)
		{"TZS local number gets prefix", "TZS", "712345678", "255712345678"},
		{"TZS already has dial code", "TZS", "255712345678", "255712345678"},
		{"TZS lowercase currency", "tzs", "255712345678", "255712345678"},
		// KES (254)
		{"KES local number gets prefix", "KES", "712345678", "254712345678"},
		{"KES already has dial code", "KES", "254712345678", "254712345678"},
		// Unknown currency: return digits only (no dial code added)
		{"NGN unknown currency returns digits", "NGN", "+2348012345678", "2348012345678"},
		{"unknown currency with spaces", "XYZ", "  701234567  ", "701234567"},
		// Edge: empty after trim
		{"empty string unchanged", "UGX", "", ""},
		{"only plus and spaces returns empty", "UGX", "  +   ", ""},
		// Separator-heavy: strip all non-digits then normalize
		{"UGX separator-heavy normalizes to digits only", "UGX", "+256 701-234-567", "256701234567"},
		// Leading non-digits stripped; already has dial code returns digitOnly
		{"UGX leading junk already has 256", "UGX", "x256701234567", "256701234567"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeMobileMoneyAccountIdentifier(tt.currencyCode, tt.accountIdentifier)
			assert.Equal(t, tt.want, got, "NormalizeMobileMoneyAccountIdentifier(%q, %q)", tt.currencyCode, tt.accountIdentifier)
		})
	}
}
