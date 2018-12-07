package api

import (
	"strings"
	"testing"
)

func TestCreateServiceRequest_ValidateDescriptions(t *testing.T) {

	tests := []struct {
		desc     string
		input    string
		expected error
	}{
		{
			desc:     "normal description",
			input:    "A valid description with !@#$%^&*()_-.",
			expected: nil,
		},
		{
			desc:     "maximum length description",
			input:    strings.Repeat("a", serviceDescriptionMaxLength),
			expected: nil,
		},
		{
			desc:     "longer than maximum length description",
			input:    strings.Repeat("a", serviceDescriptionMaxLength+1),
			expected: ErrInvalidServiceDescription,
		},
		{
			desc:     "description with non-ASCII characters",
			input:    "立显荣朝士Σumé",
			expected: nil,
		},
		{
			desc:     "description with newline",
			input:    "description\nmore",
			expected: ErrInvalidServiceDescription,
		},
		{
			desc:     "description with tab",
			input:    "description\tmore",
			expected: ErrInvalidServiceDescription,
		},
		{
			desc:     "empty description",
			input:    "",
			expected: nil,
		},
	}

	for _, test := range tests {
		err := ValidateServiceDescription(test.input)
		if err != test.expected {
			t.Errorf("test %s: returned value is not as expected: %v (actual) != %v (expected)", test.desc, err, test.expected)
		}
	}
}
