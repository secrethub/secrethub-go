package vat

import (
	"fmt"
	"regexp"
	"strings"
)

var countryNameMap = map[string]*country{}
var countryCodeMap = map[string]*country{}

func init() {
	for i := range countries {
		countryNameMap[strings.ToLower(countries[i].name)] = &countries[i]
		countryCodeMap[countries[i].code] = &countries[i]
	}
}

type country struct {
	name    string
	code    string
	pattern *regexp.Regexp
	isEU    bool
}

// For reference on the patterns, see http://ec.europa.eu/taxation_customs/vies/faqvies.do#item_11
// and https://www.gov.uk/guidance/vat-eu-country-codes-vat-numbers-and-vat-in-other-languages
var countries = []country{
	{
		name:    "Austria",
		code:    "AT",
		pattern: regex(`U[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Belgium",
		code:    "BE",
		pattern: regex(`(0[0-9]{9}|[0-9]{10})`),
		isEU:    true,
	},
	{
		name:    "Bulgaria",
		code:    "BG",
		pattern: regex(`[0-9]{9,10}`),
		isEU:    true,
	},
	{
		name:    "Croatia",
		code:    "HR",
		pattern: regex(`[0-9]{11}`),
		isEU:    true,
	},
	{
		name:    "Cyprus",
		code:    "CY",
		pattern: regex(`[0-9]{8}[A-Z]`),
		isEU:    true,
	},
	{
		name:    "Czech Republic",
		code:    "CZ",
		pattern: regex(`[0-9]{8,10}`),
		isEU:    true,
	},
	{
		name:    "Denmark",
		code:    "DK",
		pattern: regex(`[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Estonia",
		code:    "EE",
		pattern: regex(`[0-9]{9}`),
		isEU:    true,
	},
	{
		name:    "Finland",
		code:    "FI",
		pattern: regex(`[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "France",
		code:    "FR",
		pattern: regex(`[0-9A-HJ-NP-Z]{2}[0-9]{9}`),
		isEU:    true,
	},
	{
		name:    "Germany",
		code:    "DE",
		pattern: regex(`[0-9]{9}`),
		isEU:    true,
	},
	{
		name:    "Greece",
		code:    "EL",
		pattern: regex(`[0-9]{9}`),
		isEU:    true,
	},
	{
		name:    "Hungary",
		code:    "HU",
		pattern: regex(`[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Ireland",
		code:    "IE",
		pattern: regex(`[0-9]{7}[A-Z]{1,2}|[0-9][A-Z][0-9]{5}[A-Z]`),
		isEU:    true,
	},
	{
		name:    "Italy",
		code:    "IT",
		pattern: regex(`[0-9]{11}`),
		isEU:    true,
	},
	{
		name:    "Latvia",
		code:    "LV",
		pattern: regex(`[0-9]{11}`),
		isEU:    true,
	},
	{
		name:    "Lithuania",
		code:    "LT",
		pattern: regex(`([0-9]{9}|[0-9]{12})`),
		isEU:    true,
	},
	{
		name:    "Luxembourg",
		code:    "LU",
		pattern: regex(`[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Malta",
		code:    "MT",
		pattern: regex(`[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Netherlands",
		code:    "NL",
		pattern: regex(`[0-9]{9}B[0-9]{2}`),
		isEU:    true,
	},
	{
		name:    "Poland",
		code:    "PL",
		pattern: regex(`[0-9]{10}`),
		isEU:    true,
	},
	{
		name:    "Portugal",
		code:    "PT",
		pattern: regex(`[0-9]{9}`),
		isEU:    true,
	},
	{
		name:    "Romania",
		code:    "RO",
		pattern: regex(`[0-9]{2,10}`),
		isEU:    true,
	},
	{
		name:    "Slovakia",
		code:    "SK",
		pattern: regex(`[0-9]{10}`),
		isEU:    true,
	},
	{
		name:    "Slovenia",
		code:    "SI",
		pattern: regex(`[0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Spain",
		code:    "ES",
		pattern: regex(`[A-Z][0-9]{7}[A-Z]|[0-9]{8}[A-Z]|[A-Z][0-9]{8}`),
		isEU:    true,
	},
	{
		name:    "Sweden",
		code:    "SE",
		pattern: regex(`[0-9]{12}`),
		isEU:    true,
	},
	{
		name:    "United Kingdom",
		code:    "GB",
		pattern: regex(`[0-9]{9}|[0-9]{12}|(GD|HA)[0-9]{3}`),
		isEU:    true, // TODO: change this and update subscriptions before 30 March 2019 if UK Brexit negotiations
	},
}

// IsEU returns true when European VAT regulations apply to a given country.
func IsEU(country string) bool {
	c, ok := countryNameMap[strings.ToLower(country)]
	if ok {
		return c.isEU
	}
	return false
}

// regex is a helper function that compiles a string pattern into a regular expression.
func regex(pattern string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf("^(%s)$", pattern))
}
