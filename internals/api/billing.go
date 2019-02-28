package api

import (
	"net/http"
	"strings"

	"github.com/keylockerbv/secrethub-go/internals/api/vat"
)

// Errors
var (
	ErrInvalidCardToken              = errAPI.Code("invalid_card_token").StatusError("invalid card token given", http.StatusBadRequest)
	ErrInvalidCardID                 = errAPI.Code("invalid_card_id").StatusError("invalid card_id given", http.StatusBadRequest)
	ErrInvalidPlanID                 = errAPI.Code("invalid_plan_id").StatusError("invalid plan_id given", http.StatusBadRequest)
	ErrTaxIDRequired                 = errAPI.Code("tax_id_required").StatusError("for EU countries a tax_id is required", http.StatusBadRequest)
	ErrAddressDoesNotMatchTaxCountry = errAPI.Code("countries_mismatch").StatusError("address country does not match tax country", http.StatusBadRequest)
)

// Pricing defines the pricing scheme of SecretHub, with all the plans
// customers can subscribe to.
type Pricing struct {
	AnnualDiscountLabel string             `json:"annual_discount_label"`
	DefaultPlans        *DefaultPlans      `json:"default_plans"`
	Features            map[string]Feature `json:"features"`
	Plans               []*BillingPlan     `json:"plans"`
}

// DefaultPlans defines the plan ids for default plans.
type DefaultPlans struct {
	Month    string `json:"month"`
	Year     string `json:"year"`
	Personal string `json:"personal"`
}

// Feature defines a product feature included in billing plans.
type Feature struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// BillingPlan defines a plan for billing customers.
type BillingPlan struct {
	ID              string          `json:"id"` // short tag shared across Stripe plans that together form this plan
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Currency        string          `json:"currency"` // eur
	BaseFee         *FixedFee       `json:"base_fee"`
	PerSecretFee    *MeteredFee     `json:"per_secret_fee,omitempty"`
	MaxMembers      int             `json:"max_members"`
	Features        []string        `json:"features"`
	TrialPeriodDays int64           `json:"trial_period_days"`
	Type            BillingPlanType `json:"type"`
}

// BillingPlanType is used to distinguish between different types of plans.
type BillingPlanType string

const (
	// BillingPlanTypeDefault defines default plans selectable by the user.
	BillingPlanTypeDefault BillingPlanType = "default"
	// BillingPlanTypePersonal defines personal plans.
	BillingPlanTypePersonal BillingPlanType = "personal"
	// BillingPlanTypeCustom defines custom plans that need to be handled differently.
	BillingPlanTypeCustom BillingPlanType = "custom"
	// BillingPlanTypePromo defines plans used for promotional purposes.
	BillingPlanTypePromo BillingPlanType = "promo"
)

// FixedFee defines a fixed price for a subscription billed at a given interval.
type FixedFee struct {
	Name     string `json:"name"`
	Interval string `json:"interval"`
	Price    int64  `json:"price"`
}

// MeteredFee defines a metered price for a subscription billed at a given interval,
// per units defined in the tiers.
type MeteredFee struct {
	Name     string        `json:"name"`
	Interval string        `json:"interval"`
	Tiers    []MeteredTier `json:"tiers"`
}

// MeteredTier defines a price per unit up to a given number of units.
type MeteredTier struct {
	Price int64 `json:"price"`
	UpTo  int64 `json:"up_to"`
}

// Subscription defines a billing plan a customer has subscribed to.
type Subscription struct {
	Plan       *BillingPlan       `json:"plan"`
	Fees       []*SubscriptionFee `json:"fees"`
	TaxPercent float64            `json:"tax_percent"`
}

// SubscriptionFee defines a fee included in a subscription, which the customer
// will be billed for. Each fee has their own charge and billing cycle.
type SubscriptionFee struct {
	Name               string `json:"name"`
	Status             string `json:"status"`
	CurrentPeriodEnd   int64  `json:"current_period_end"`
	CurrentPeriodStart int64  `json:"current_period_start"`
	TrialEnd           int64  `json:"trial_end"`
	TrialStart         int64  `json:"trial_start"`
}

// UpdateSubscriptionRequest defines a request for adding or updating a subscription.
type UpdateSubscriptionRequest struct {
	PlanID string `json:"plan_id"`
}

// Validate validates a UpdateSubscriptionRequest
func (r UpdateSubscriptionRequest) Validate() error {
	if r.PlanID == "" {
		return ErrInvalidPlanID
	}
	return nil
}

// CreditCard defines a card used for payments.
type CreditCard struct {
	CardID   string `json:"card_id"`
	Brand    string `json:"brand"`
	ExpMonth uint8  `json:"exp_month"`
	ExpYear  uint16 `json:"exp_year"`
	Last4    string `json:"last_4"`
}

// CreateCardRequest defines the request fields for creating a new credit card.
type CreateCardRequest struct {
	Token string `json:"token"`
}

// Validate validates the request fields.
func (r CreateCardRequest) Validate() error {
	if strings.HasPrefix(r.Token, "tok_") {
		return nil
	}
	return ErrInvalidCardToken
}

// BillingInfo contains the billing information of a customer and determines
// what will be put on invoices sent to the customer.
type BillingInfo struct {
	CustomerID     string         `json:"customer_id"`
	CompanyDetails CompanyDetails `json:"company_details"`
	Email          string         `json:"email"`
	DefaultCardID  string         `json:"default_card_id"`
	Cards          []*CreditCard  `json:"cards"`
}

// CompanyDetails contains the billing details of a customer's company that will
// be put on invoices sent to the customer.
type CompanyDetails struct {
	Address    string     `json:"address"`
	City       string     `json:"city"`
	Name       string     `json:"name"`
	Country    string     `json:"country"`
	PostalCode string     `json:"postal_code"`
	TaxID      vat.Number `json:"tax_id"`
}

// BillingInfoParams defines the optional customer detail fields that can be set.
type BillingInfoParams struct {
	CompanyDetails *CompanyDetailsParams `json:"company_details,omitempty"`
	Email          *string               `json:"email,omitempty"`
	DefaultCardID  *string               `json:"default_card_id,omitempty"` // optional, cannot be unset
}

// Validate validates the request fields.
func (c *BillingInfoParams) Validate() error {
	if c.CompanyDetails != nil {
		err := c.CompanyDetails.Validate()
		if err != nil {
			return err
		}
	}

	if c.Email != nil {
		err := ValidateEmail(*c.Email)
		if err != nil {
			return err
		}
	}

	if c.DefaultCardID != nil {
		err := validateCardID(*c.DefaultCardID)
		if err != nil {
			return err
		}
	}

	return nil
}

// CompanyDetailsParams are used to update a customer's company details.
type CompanyDetailsParams struct {
	Address    string     `json:"address"`
	City       string     `json:"city"`
	Name       string     `json:"name"`
	Country    string     `json:"country"`
	PostalCode string     `json:"postal_code"`
	TaxID      vat.Number `json:"tax_id"` // required for EU countries, optional for non-EU countries
}

// Validate validates the parameters.
func (p *CompanyDetailsParams) Validate() error {
	if p.Address == "" {
		return errInvalidCompanyDetails("address")
	}

	if p.City == "" {
		return errInvalidCompanyDetails("city")
	}

	if p.Country == "" {
		return errInvalidCompanyDetails("country")
	}

	if p.Name == "" {
		return errInvalidCompanyDetails("name")
	}

	if p.PostalCode == "" {
		return errInvalidCompanyDetails("postal_code")
	}

	if vat.IsEU(p.Country) {
		// Require a valid TaxID for EU customers
		if p.TaxID == "" {
			return ErrTaxIDRequired
		}

		err := p.TaxID.Validate()
		if err != nil {
			return err
		}

		// Ensure the country matches the taxID given.
		if !strings.EqualFold(p.TaxID.Country(), p.Country) {
			return ErrAddressDoesNotMatchTaxCountry
		}
	}

	return nil
}

// validateCardID returns an error when the given cardID does not match the length and prefix
// of Stripe card IDs.
func validateCardID(cardID string) error {
	if !strings.HasPrefix(cardID, "card_") || len(cardID) != 29 {
		return ErrInvalidCardID
	}
	return nil
}

// errInvalidCompanyDetails is a helper function to create errors for different invalid fields.
func errInvalidCompanyDetails(field string) error {
	return errAPI.Code("invalid_company_details").StatusErrorf("invalid company details field: %s", http.StatusBadRequest, field)
}
