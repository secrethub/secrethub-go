package api_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/testutil"
)

func TestValidateOrgDescription(t *testing.T) {
	// Arrange
	tests := []struct {
		descr    string
		expected error
	}{
		{
			descr:    "",
			expected: nil,
		},
		{
			descr:    "aa",
			expected: nil,
		},
		{
			descr:    "with whitespace",
			expected: nil,
		},
		{
			descr:    "with: punctuation.",
			expected: nil,
		},
		{
			descr:    "with numbers 0123456789",
			expected: nil,
		},
		{
			descr:    "with weird characters Ω",
			expected: nil,
		},
		{
			descr:    strings.Repeat("144", 48),
			expected: nil,
		},
		{
			descr:    strings.Repeat("144", 48) + "1",
			expected: api.ErrInvalidDescription,
		},
	}

	for _, test := range tests {
		// Act
		actual := api.ValidateOrgDescription(test.descr)

		// Assert
		if actual != test.expected {
			t.Errorf("unexpected result for description `%s`:\n%v (actual) != %v (expected)", test.descr, actual, test.expected)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	// Arrange
	tests := map[string]struct {
		username string
		expected error
	}{
		"success": {
			username: "test.USER_1",
			expected: nil,
		},
		"empty": {
			username: "",
			expected: api.ErrInvalidUsername,
		},
		"no alphanumeric": {
			username: "_-_.",
			expected: api.ErrUsernameMustContainAlphanumeric,
		},
		"too short": {
			username: "ab",
			expected: api.ErrInvalidUsername,
		},
		"32 characters long": {
			username: strings.Repeat("a", 32),
			expected: nil,
		},
		"33 characters long": {
			username: strings.Repeat("a", 32) + "a",
			expected: api.ErrInvalidUsername,
		},
		"is a service": {
			username: "s-service",
			expected: api.ErrUsernameIsService,
		},
		"invalid character": {
			username: "test_user+",
			expected: api.ErrInvalidUsername,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Act
			actual := api.ValidateUsername(tc.username)

			// Assert
			testutil.CompareDescribe(t, "returned validation error not as expected", actual, tc.expected)
		})
	}
}

func TestValidateOrgName(t *testing.T) {
	// Arrange
	tests := map[string]struct {
		orgName  string
		expected error
	}{
		"success": {
			orgName:  "test.ORG_1",
			expected: nil,
		},
		"empty": {
			orgName:  "",
			expected: api.ErrInvalidOrgName,
		},
		"no alphanumeric": {
			orgName:  "_-_.",
			expected: api.ErrOrgNameMustContainAlphanumeric,
		},
		"too short": {
			orgName:  "ab",
			expected: api.ErrInvalidOrgName,
		},
		"32 characters long": {
			orgName:  strings.Repeat("a", 32),
			expected: nil,
		},
		"33 characters long": {
			orgName:  strings.Repeat("a", 32) + "a",
			expected: api.ErrInvalidOrgName,
		},
		"invalid character": {
			orgName:  "test_org+",
			expected: api.ErrInvalidOrgName,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Act
			actual := api.ValidateOrgName(tc.orgName)

			// Assert
			testutil.CompareDescribe(t, "returned validation error not as expected", actual, tc.expected)
		})
	}
}

func TestValidateRepoName(t *testing.T) {
	// Arrange
	tests := map[string]struct {
		repoName string
		expected error
	}{
		"success": {
			repoName: "test.REPO_1",
			expected: nil,
		},
		"empty": {
			repoName: "",
			expected: api.ErrInvalidRepoName,
		},
		"short": {
			repoName: "ab",
			expected: nil,
		},
		"32 characters long": {
			repoName: strings.Repeat("a", 32),
			expected: nil,
		},
		"33 characters long": {
			repoName: strings.Repeat("a", 32) + "a",
			expected: api.ErrInvalidRepoName,
		},
		"invalid character": {
			repoName: "test_repo+",
			expected: api.ErrInvalidRepoName,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Act
			actual := api.ValidateRepoName(tc.repoName)

			// Assert
			testutil.CompareDescribe(t, "returned validation error not as expected", actual, tc.expected)
		})
	}
}

func TestValidateSecretName(t *testing.T) {
	// Arrange
	tests := map[string]struct {
		secretName string
		expected   error
	}{
		"success": {
			secretName: "test.SECRET_1",
			expected:   nil,
		},
		"empty": {
			secretName: "",
			expected:   api.ErrInvalidSecretName,
		},
		"short": {
			secretName: "ab",
			expected:   nil,
		},
		"only dot": {
			secretName: ".",
			expected:   api.ErrInvalidSecretName,
		},
		"only multiple dots": {
			secretName: "...",
			expected:   api.ErrInvalidSecretName,
		},
		"32 characters long": {
			secretName: strings.Repeat("a", 32),
			expected:   nil,
		},
		"33 characters long": {
			secretName: strings.Repeat("a", 32) + "a",
			expected:   api.ErrInvalidSecretName,
		},
		"invalid character": {
			secretName: "test_secret+",
			expected:   api.ErrInvalidSecretName,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Act
			actual := api.ValidateSecretName(tc.secretName)

			// Assert
			testutil.CompareDescribe(t, "returned validation error not as expected", actual, tc.expected)
		})
	}
}

func TestValidateBlindName_BlindNamePath(t *testing.T) {
	// This test is coupled with BlindNamePath interface implementors to test if their implementations are validated.
	key, err := crypto.GenerateAESKey()
	testutil.OK(t, err)

	// Arrange
	tests := map[string]struct {
		path api.BlindNamePath
	}{
		"SecretPath": {
			path: api.SecretPath("owner/repo/grandparent/dir/secret"),
		},
		"DirPath": {
			path: api.DirPath("owner/repo/grandparent/dir"),
		},
		"ParentPath": {
			path: api.ParentPath("owner/repo/grandparent"),
		},
		"ParentPath at repo root": {
			path: api.ParentPath("owner/repo"),
		},
		"RepoPath": {
			path: api.RepoPath("owner/repo"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, err := test.path.BlindName(key)
			validationErr := api.ValidateBlindName(actual)

			// Assert
			testutil.Compare(t, err, nil)
			testutil.Compare(t, validationErr, nil)
		})
	}
}

func TestValidateBlindName(t *testing.T) {
	// Arrange
	tests := []struct {
		blindName string
	}{
		{
			blindName: "notBase64Encoded",
		},
		{
			blindName: base64.URLEncoding.EncodeToString([]byte{1, 2, 3}),
		},
	}

	for _, test := range tests {
		// Act
		actual := api.ValidateBlindName(test.blindName)

		// Assert
		if actual != api.ErrInvalidBlindName {
			t.Errorf("unexpected error for path `%s`:\n%v (actual) != %v (expected)\n", test.blindName, actual, api.ErrInvalidBlindName)
		}
	}
}

func TestValidateDirPath(t *testing.T) {
	// Arrange
	tests := []struct {
		path     api.DirPath
		expected error
	}{
		{
			path:     "owner/repo/grandparent/parent1/child1",
			expected: nil,
		},
		{
			path:     "owner/repo",
			expected: nil,
		},
	}

	for _, test := range tests {
		// Act
		actual := test.path.Validate()

		// Assert
		if actual != test.expected {
			t.Errorf("unexpected error for path `%s`:\n%v (actual) != %v (expected)\n", test.path, actual, test.expected)
		}
	}
}

func TestValidateSecretPath(t *testing.T) {
	// Arrange
	tests := []struct {
		path  api.SecretPath
		valid bool
	}{
		{
			path:  "namespace/repo/secret",
			valid: true,
		},
		{
			path:  "namespace/repo/parent/secret",
			valid: true,
		},
		{
			path:  "namespace/repo/secret:1",
			valid: true,
		},
		{
			path:  "namespace/repo/parent/secret:1",
			valid: true,
		},
		{
			path:  "namespace/repo/secret:latest",
			valid: true,
		},
		{
			path:  "namespace/repo/parent/secret:latest",
			valid: true,
		},
		{
			path:  "namespace/repo/",
			valid: false,
		},
		{
			path:  "namespace/repo/+",
			valid: false,
		},
		{
			path:  "namespace/repo/parent/+",
			valid: false,
		},
		{
			path:  "namespace/repo/dir/",
			valid: false,
		},
		{
			path:  "namespace",
			valid: false,
		},
		{
			path:  "namespace/repo",
			valid: false,
		},
		{
			path:  "/repo/secret",
			valid: false,
		},
		{
			path:  "/namespace/repo/secret",
			valid: false,
		},
	}

	for _, test := range tests {
		// Act
		err := api.ValidateSecretPath(string(test.path))

		// Assert
		if err != nil && test.valid {
			t.Errorf(
				"unexpected error for path %s:\n\t%v (actual) != <nil> (expected)",
				test.path,
				err,
			)
		} else if err == nil && !test.valid {
			t.Errorf(
				"unexpected error for path %s:\n\t%v (actual) != ErrInvalidSecretPath (expected)",
				test.path,
				err,
			)
		}
	}
}
