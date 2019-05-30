package vat

import (
	"strings"
)

// DefaultRates defines the rates for a business located in the Netherlands.
var DefaultRates = NewRates("Netherlands", 21.0, true)

// Rates helps dealing with tax rates in different countries.
type Rates interface {
	GetTaxRate(country string) (float64, bool)
}

type rates struct {
	sellerCountry string
	isEU          bool
	rate          float64
}

// NewRates returns the rates for a business selling goods
func NewRates(sellerCountry string, rate float64, isEU bool) Rates {
	return &rates{
		sellerCountry: strings.ToLower(sellerCountry),
		isEU:          isEU,
		rate:          rate,
	}
}

// GetTaxRate returns the tax rate for a customer in a given country,
// returning true when the EU reverse charge scheme applies to the rate.
func (r *rates) GetTaxRate(country string) (float64, bool) {
	country = strings.ToLower(country)
	if country == r.sellerCountry {
		return r.rate, false
	}

	if r.isEU && IsEU(country) {
		return 0.0, true
	}

	return 0.0, false
}
