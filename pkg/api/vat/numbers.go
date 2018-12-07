package vat

import (
	"net/http"

	"github.com/keylockerbv/secrethub/core/errio"
)

// Errors
var (
	errors            = errio.Namespace("vat")
	ErrNumberTooShort = errors.Code("invalid_number_too_short").StatusError("number is too short", http.StatusBadRequest)
)

// Number defines a VAT number.
type Number string

// Country returns the name of the country associated with the VAT number.
func (n Number) Country() string {
	country, ok := countryCodeMap[n.CountryCode()]
	if !ok {
		return ""
	}
	return country.name
}

// CountryCode returns the country code of a VAT number.
func (n Number) CountryCode() string {
	if len(n) < 2 {
		return ""
	}

	return string(n)[:2]
}

// Validate validates a VAT number, returning nil for numbers with an unknown country code.
func (n Number) Validate() error {
	if len(n) < 2 {
		return ErrNumberTooShort
	}

	country, ok := countryCodeMap[n.CountryCode()]
	if !ok {
		// We don't validate numbers with unknown country codes.
		return nil
	}

	if !country.pattern.Match([]byte(n[2:])) {
		return errors.Code("invalid_number_for_country").StatusErrorf("invalid VAT number for %s: %s", http.StatusBadRequest, country.name, n)
	}

	return nil
}

func (n Number) String() string {
	return string(n)
}

// IsErrInvalidNumber returns true when a given error is of type invalid_number.
// TODO: make this work nicely.
func IsErrInvalidNumber(err error) bool {
	e, ok := err.(*errio.PublicError)
	if !ok {
		return false
	}

	return e.Code == "invalid_number"
}
