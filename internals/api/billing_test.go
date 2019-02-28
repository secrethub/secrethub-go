package api

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/internals/assert"
)

func strPtr(s string) *string {
	return &s
}

func TestValidateBillingInfoParams(t *testing.T) {
	cases := map[string]struct {
		params *BillingInfoParams
		err    error
	}{
		"empty": {
			params: &BillingInfoParams{},
			err:    nil,
		},
		"invalid company details": {
			params: &BillingInfoParams{
				CompanyDetails: &CompanyDetailsParams{},
			},
			err: errInvalidCompanyDetails("address"),
		},
		"empty email": {
			params: &BillingInfoParams{
				Email: strPtr(""),
			},
			err: ErrInvalidEmail,
		},
		"invalid email": {
			params: &BillingInfoParams{
				Email: strPtr("invalid_email"),
			},
			err: ErrInvalidEmail,
		},
		"invalid default_card_id": {
			params: &BillingInfoParams{
				Email:         strPtr("test-account@secrethub.io"),
				DefaultCardID: strPtr("invalid_card_id"),
			},
			err: ErrInvalidCardID,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tc.params.Validate()

			// Assert
			assert.Equal(t, err, tc.err)
		})
	}
}

func TestValidateCompanyDetailsParams(t *testing.T) {
	cases := map[string]struct {
		params *CompanyDetailsParams
		err    error
	}{
		"empty address": {
			params: &CompanyDetailsParams{
				Address: "",
			},
			err: errInvalidCompanyDetails("address"),
		},
		"empty city": {
			params: &CompanyDetailsParams{
				Address: "Molengraaffsingel 10",
				City:    "",
			},
			err: errInvalidCompanyDetails("city"),
		},
		"empty country": {
			params: &CompanyDetailsParams{
				Address: "Molengraaffsingel 10",
				City:    "Delft",
				Country: "",
			},
			err: errInvalidCompanyDetails("country"),
		},
		"empty company name": {
			params: &CompanyDetailsParams{
				Address: "Molengraaffsingel 10",
				City:    "Delft",
				Country: "Netherlands",
				Name:    "",
			},
			err: errInvalidCompanyDetails("name"),
		},
		"empty postal code": {
			params: &CompanyDetailsParams{
				Address:    "Molengraaffsingel 10",
				City:       "Delft",
				Country:    "Netherlands",
				Name:       "SecretHub",
				PostalCode: "",
			},
			err: errInvalidCompanyDetails("postal_code"),
		},
		"tax_id required": {
			params: &CompanyDetailsParams{
				Address:    "Molengraaffsingel 10",
				City:       "Delft",
				Country:    "Netherlands",
				Name:       "SecretHub",
				PostalCode: "2613SN",
				TaxID:      "",
			},
			err: ErrTaxIDRequired,
		},
		"no tax_id required": {
			params: &CompanyDetailsParams{
				Address:    "428 Green Avenue",
				City:       "San Francisco",
				Name:       "Freedom Unlimited",
				Country:    "United States",
				PostalCode: "94107",
				TaxID:      "",
			},
			err: nil,
		},
		"countries mismatch": {
			params: &CompanyDetailsParams{
				Address:    "Molengraaffsingel 10",
				City:       "Delft",
				Country:    "Netherlands",
				Name:       "SecretHub",
				PostalCode: "2613SN",
				TaxID:      "IT12345678901",
			},
			err: ErrAddressDoesNotMatchTaxCountry,
		},
		"countries match diff case": {
			params: &CompanyDetailsParams{
				Address:    "Molengraaffsingel 10",
				City:       "Delft",
				Country:    "NETHERLANDS",
				Name:       "SecretHub",
				PostalCode: "2613SN",
				TaxID:      "NL123456789B01",
			},
			err: nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tc.params.Validate()

			// Assert
			assert.Equal(t, err, tc.err)
		})
	}
}
