package vat

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
)

func TestGetTaxRate(t *testing.T) {
	cases := map[string]struct {
		buyer    string
		expected float64
		reverse  bool
	}{
		"to NL": {
			buyer:    "Netherlands",
			expected: 21.0,
			reverse:  false,
		},
		"to NL diff case": {
			buyer:    "netherlands",
			expected: 21.0,
			reverse:  false,
		},
		"to EU": {
			buyer:    "Belgium",
			expected: 0.0,
			reverse:  true,
		},
		"to EU diff case": {
			buyer:    "belgium",
			expected: 0.0,
			reverse:  true,
		},
		"to US": {
			buyer:    "United States",
			expected: 0.0,
			reverse:  false,
		},
	}

	rates := DefaultRates

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, reverse := rates.GetTaxRate(tc.buyer)

			// Assert
			testutil.Compare(t, actual, tc.expected)
			testutil.Compare(t, reverse, tc.reverse)
		})
	}
}
