package aws

import (
	"fmt"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func Test_parseRole(t *testing.T) {
	defaultAccountID := "1234567890"
	defaultARN := fmt.Sprintf("arn:aws:iam::%s:role/RoleName", defaultAccountID)

	cases := map[string]struct {
		role        string
		accountID   string
		expected    string
		expectedErr error
	}{
		"role name only": {
			role:      "RoleName",
			accountID: "1234567890",
			expected:  defaultARN,
		},
		"with role prefix": {
			role:      "role/RoleName",
			accountID: "1234567890",
			expected:  defaultARN,
		},
		"complete ARN": {
			role:      defaultARN,
			accountID: "1234567890",
			expected:  defaultARN,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			getAccountID := func() (string, error) {
				return tc.accountID, nil
			}
			actual, err := parseRole(tc.role, getAccountID)
			assert.Equal(t, actual, tc.expected)
			assert.Equal(t, err, tc.expectedErr)
		})
	}
}
