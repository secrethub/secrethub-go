package vat

import "testing"

func TestValidate(t *testing.T) {
	cases := map[string]struct {
		valid   []string
		invalid []string
	}{
		"corner_cases": {
			invalid: []string{"", " "},
		},
		"Austria": {
			valid: []string{
				"ATU12345678",
			},
			invalid: []string{
				"ATU1234567",
				"ATU123456789",
				"ATA12345678",
				"ATU1234567A",
			},
		},
		"Belgium": {
			valid: []string{
				"BE0123456789",
				"BE1234567890",
			},
			invalid: []string{
				"BE123456789",
				"BE12345678901",
				"BE012345678A",
				"BE123456789A",
			},
		},
		"Bulgaria": {
			valid: []string{
				"BG123456789",
				"BG1234567890",
			},
			invalid: []string{
				"BG12345678",
				"BG12345678901",
				"BG12345678A",
				"BG123456789A",
			},
		},
		"Croatia": {
			valid: []string{
				"HR12345678901",
			},
			invalid: []string{
				"HR1234567890",
				"HR123456789012",
				"HR123456789A",
			},
		},
		"Cyprus": {
			valid: []string{
				"CY12345678A",
				"CY12345678Z",
			},
			invalid: []string{
				"CY123456789",
				"CY12345678",
				"CY1234567A",
				"CY123456789A",
				"CY1234567890",
			},
		},
		"Czech Republic": {
			valid: []string{
				"CZ12345678",
				"CZ123456789",
				"CZ1234567890",
			},
			invalid: []string{
				"CZ1234567",
				"CZ12345678901",
				"CZ123456A",
				"CZ123456789A",
			},
		},
		"Denmark": {
			valid: []string{
				"DK12345678",
			},
			invalid: []string{
				"DK1234567",
				"DK123456789",
				"DK123456A",
			},
		},
		"Estonia": {
			valid: []string{
				"EE123456789",
			},
			invalid: []string{
				"EE12345678",
				"EE1234567890",
				"EE1234568A",
			},
		},
		"Finland": {
			valid: []string{
				"FI12345678",
			},
			invalid: []string{
				"FI1234567",
				"FI123456789",
				"FI123456A",
			},
		},
		"France": {
			valid: []string{
				"FR12345678901",
				"FRX1234567890",
				"FR1X123456789",
				"FRXX123456789",
			},
			invalid: []string{
				"FRXX12345678",
				"FRXX1234567890",
				"FR12X45678901",
				"FRI1234567890",
				"FRO1234567890",
				"FR1I123456789",
				"FR1O123456789",
				"FRII123456789",
				"FROO123456789",
			},
		},
		"Germany": {
			valid: []string{
				"DE123456789",
			},
			invalid: []string{
				"DE12345678",
				"DE1234567890",
				"DE1234568A",
			},
		},
		"Greece": {
			valid: []string{
				"EL123456789",
			},
			invalid: []string{
				"EL12345678",
				"EL1234567890",
				"EL12345678A",
			},
		},
		"Hungary": {
			valid: []string{
				"HU12345678",
			},
			invalid: []string{
				"HU1234567",
				"HU123456789",
				"HU1234567A",
			},
		},
		"Ireland": {
			valid: []string{
				"IE1234567X",
				"IE1X23456X",
				"IE1234567XX",
			},
			invalid: []string{
				"IE12345678",
				"IE1234567X8",
				"IE123456X",
				"IE1234567XXX",
				"IEX123456X",
			},
		},
		"Italy": {
			valid: []string{
				"IT12345678901",
			},
			invalid: []string{
				"IT1234567890",
				"IT123456789012",
				"IT1234567890A",
			},
		},
		"Latvia": {
			valid: []string{
				"LV12345678901",
			},
			invalid: []string{
				"LV1234567890",
				"LV123456789012",
				"LV1234567890A",
			},
		},
		"Lithuania": {
			valid: []string{
				"LT123456789",
				"LT123456789012",
			},
			invalid: []string{
				"LT12345678",
				"LT1234567890",
				"LT12345678901",
				"LT1234567890123",
				"LT12345678A",
			},
		},
		"Luxembourg": {
			valid: []string{
				"LU12345678",
			},
			invalid: []string{
				"LU1234567",
				"LU123456789",
				"LU1234567A",
			},
		},
		"Malta": {
			valid: []string{
				"MT12345678",
			},
			invalid: []string{
				"MT1234567",
				"MT123456789",
				"MT1234567A",
			},
		},
		"Netherlands": {
			valid: []string{
				"NL123456789B01",
			},
			invalid: []string{
				"NL123456789012",
				"NL123456789B012",
				"NL123456789B0",
			},
		},
		"Poland": {
			valid: []string{
				"PL1234567890",
			},
			invalid: []string{
				"PL123456789",
				"PL12345678901",
				"PL123456789A",
			},
		},
		"Portugal": {
			valid: []string{
				"PT123456789",
			},
			invalid: []string{
				"PT12345678",
				"PT1234567890",
				"PT12345678A",
			},
		},
		"Romania": {
			valid: []string{
				"RO12",
				"RO123",
				"RO1234",
				"RO12345",
				"RO123456",
				"RO1234567",
				"RO12345678",
				"RO123456789",
				"RO1234567890",
			},
			invalid: []string{
				"RO1",
				"RO12345678901",
				"RO123456789A",
			},
		},
		"Slovakia": {
			valid: []string{
				"SK1234567890",
			},
			invalid: []string{
				"SK123456789",
				"SK12345678901",
				"SK123456789A",
			},
		},
		"Slovenia": {
			valid: []string{
				"SI12345678",
			},
			invalid: []string{
				"SI1234567",
				"SI123456789",
				"SI1234567A",
			},
		},
		"Spain": {
			valid: []string{
				"ESX12345678",
				"ES12345678X",
				"ESX1234567X",
			},
			invalid: []string{
				"ES123456789",
				// TODO: more invalid cases
			},
		},
		"Sweden": {
			valid: []string{
				"SE123456789012",
			},
			invalid: []string{
				"SE12345678901",
				"SE1234567890123",
				"SE12345678901A",
			},
		},
		"United Kingdom": {
			valid: []string{
				"GB123456789",
				"GB123456789012",
				"GBGD123",
				"GBHA123",
			},
			// TODO: add invalid cases
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, n := range tc.valid {
				err := Number(n).Validate()
				if err != nil {
					t.Errorf("unexpected error for valid VAT number %s: %v (actual) != nil (expected)", n, err)
				}
			}

			for _, n := range tc.invalid {
				err := Number(n).Validate()
				if err == nil {
					t.Errorf("unexpected error for invalid VAT number %s: nil (actual) != <invalid number error> (expected)", n)
				}
			}
		})
	}
}
