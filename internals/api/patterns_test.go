package api_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/internals/crypto"
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
			assert.Equal(t, actual, tc.expected)
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
			assert.Equal(t, actual, tc.expected)
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
			assert.Equal(t, actual, tc.expected)
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
			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestValidateBlindName_BlindNamePath(t *testing.T) {
	// This test is coupled with BlindNamePath interface implementors to test if their implementations are validated.
	key, err := crypto.GenerateSymmetricKey()
	assert.OK(t, err)

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
			assert.Equal(t, err, nil)
			assert.Equal(t, validationErr, nil)
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

func TestValidateCredentialFingerprint(t *testing.T) {
	cases := map[string]struct {
		in       string
		expected error
	}{
		"valid lowercase": {
			in: "d9db31d1bfd9a8a55a4dd715501017fd8d2c33025cb05049664eaf195dafb801",
		},
		"valid uppercase": {
			in: "D9DB31D1BFD9A8A55A4DD715501017FD8D2C33025CB05049664EAF195DAFB801",
		},
		"valid mixed case": {
			in: "d9db31d1bfd9a8a55a4dd715501017FD8D2C33025CB05049664EAF195DAFB801",
		},
		"too short": {
			in:       "d9db31d1bfd9a8a55a4dd715501017fd8d2c33025cb05049664eaf195dafb80",
			expected: api.ErrInvalidFingerprint,
		},
		"too long": {
			in:       "d9db31d1bfd9a8a55a4dd715501017fd8d2c33025cb05049664eaf195dafb801b",
			expected: api.ErrInvalidFingerprint,
		},
		"illegal character": {
			in:       "Q9db31d1bfd9a8a55a4dd715501017fd8d2c33025cb05049664eaf195dafb801",
			expected: api.ErrInvalidFingerprint,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := api.ValidateCredentialFingerprint(tc.in)

			assert.Equal(t, err, tc.expected)
		})
	}
}

func TestValidateGCPServiceAccountEmail(t *testing.T) {
	cases := map[string]struct {
		in        string
		expectErr bool
	}{
		"user  managed service account": {
			in: "test-service-account@secrethub-test-1234567890.iam.gserviceaccount.com",
		},
		"appspot service account": {
			in:        "secrethub-1234567890@appspot.gserviceaccount.com",
			expectErr: true,
		},
		"compute service account": {
			in:        "secrethub-1234567890-compute@developer.gserviceaccount.com",
			expectErr: true,
		},
		"google managed service account": {
			in:        "secrethub-1234567890@cloudservices.gserviceaccount.com",
			expectErr: true,
		},
		"not an email": {
			in:        "cloudservices.gserviceaccount.com",
			expectErr: true,
		},
		"non-service account email": {
			in:        "serviceaccount@secrethub.io",
			expectErr: true,
		},
		"empty string": {
			in:        "",
			expectErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := api.ValidateGCPServiceAccountEmail(tc.in)

			assert.Equal(t, err != nil, tc.expectErr)
		})
	}
}

func TestProjectIDFromGCPEmail(t *testing.T) {
	cases := map[string]struct {
		in        string
		expectErr bool
		expect    string
	}{
		"user  managed service account": {
			in:     "test-service-account@secrethub-test-1234567890.iam.gserviceaccount.com",
			expect: "secrethub-test-1234567890",
		},
		"invalid email": {
			in:        "secrethub-1234567890-compute@developer.gserviceaccount.com",
			expectErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			projectID, err := api.ProjectIDFromGCPEmail(tc.in)

			assert.Equal(t, err != nil, tc.expectErr)
			if !tc.expectErr {
				assert.Equal(t, projectID, tc.expect)
			}
		})
	}
}

func TestValidateGCPKMSKeyResourceID(t *testing.T) {
	cases := map[string]struct {
		in        string
		expectErr bool
	}{
		"valid": {
			in: "projects/secrethub-test-1234567890/locations/global/keyRings/test/cryptoKeys/test",
		},
		"kerying only": {
			in:        "projects/secrethub-test-1234567890/locations/global/keyRings/test",
			expectErr: true,
		},
		"too many segment": {
			in:        "projects/secrethub-test-1234567890/locations/global/keyRings/test/cryptoKeys/test/extrasegment",
			expectErr: true,
		},
		"empty string": {
			in:        "",
			expectErr: true,
		},
		"missing required path segment": {
			in:        "projects/secrethub-test-1234567890//global/keyRings/test/cryptoKeys/test",
			expectErr: true,
		},
		"wrong required path segment": {
			in:        "projects/secrethub-test-1234567890/locations/global/thingiswrong/test/cryptoKeys/test",
			expectErr: true,
		},
		"leading slash": {
			in:        "/projects/secrethub-test-1234567890/locations/global/keyRings/test/cryptoKeys/test",
			expectErr: true,
		},
		"trailing slash": {
			in:        "projects/secrethub-test-1234567890/locations/global/keyRings/test/cryptoKeys/test/",
			expectErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := api.ValidateGCPKMSKeyResourceID(tc.in)

			assert.Equal(t, err != nil, tc.expectErr)
		})
	}
}
