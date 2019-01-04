package api_test

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
	"github.com/keylockerbv/secrethub-go/pkg/api"
)

func TestPermission_Set(t *testing.T) {
	testCases := []struct {
		input string
		value api.Permission
		err   error
	}{
		{
			input: "r",
			value: api.PermissionRead,
			err:   nil,
		},
		{
			input: "read",
			value: api.PermissionRead,
			err:   nil,
		},
		{
			input: "w",
			value: api.PermissionWrite,
			err:   nil,
		},
		{
			input: "write",
			value: api.PermissionWrite,
			err:   nil,
		},
		{
			input: "a",
			value: api.PermissionAdmin,
			err:   nil,
		},
		{
			input: "admin",
			value: api.PermissionAdmin,
			err:   nil,
		},
		{
			input: "n",
			value: api.PermissionNone,
			err:   nil,
		},
		{
			input: "none",
			value: api.PermissionNone,
			err:   nil,
		},
		{
			input: "unknown",
			err:   api.ErrAccessLevelUnknown,
		},
		{
			input: "rw",
			err:   api.ErrAccessLevelUnknown,
		},
		{
			input: "rwa",
			err:   api.ErrAccessLevelUnknown,
		},
		{
			input: "readwrite",
			err:   api.ErrAccessLevelUnknown,
		},
		{
			input: "man",
			err:   api.ErrAccessLevelUnknown,
		},
	}

	for _, testCase := range testCases {
		var accessLevel api.Permission
		actual := accessLevel.Set(testCase.input)
		testutil.Compare(t, actual, testCase.err)
		testutil.Compare(t, accessLevel, testCase.value)
	}
}
