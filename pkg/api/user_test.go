package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		desc     string
		input    string
		expected error
	}{
		{
			desc:     "normal username",
			input:    "User1",
			expected: nil,
		},
		{
			desc:     "username with allowed special characters",
			input:    "us.er-1_go",
			expected: nil,
		},
		{
			desc:     "minimum length username",
			input:    strings.Repeat("a", uniformNameMinimumLength),
			expected: nil,
		},
		{
			desc:     "shorter than minimum length username",
			input:    strings.Repeat("a", uniformNameMinimumLength-1),
			expected: ErrInvalidUsername,
		},
		{
			desc:     "maximum length username",
			input:    strings.Repeat("a", uniformNameMaximumLength),
			expected: nil,
		},
		{
			desc:     "longer than maximum length username",
			input:    strings.Repeat("a", uniformNameMaximumLength+1),
			expected: ErrInvalidUsername,
		},
		{
			desc:     "username with non-ASCII characters",
			input:    "usér1",
			expected: ErrInvalidUsername,
		},
		{
			desc:     "username with newline",
			input:    "username\nmore",
			expected: ErrInvalidUsername,
		},
		{
			desc:     "username with tab",
			input:    "uername\tmore",
			expected: ErrInvalidUsername,
		},
		{
			desc:     "empty username",
			input:    "",
			expected: ErrInvalidUsername,
		},
		{
			desc:     "empty username",
			input:    "",
			expected: ErrInvalidUsername,
		},
		{
			desc:     "username with service prefix",
			input:    "s-user1",
			expected: ErrUsernameIsService,
		},
		{
			desc:     "username with capital service prefix",
			input:    "S-user1",
			expected: ErrUsernameIsService,
		},
	}

	for _, test := range tests {
		err := ValidateUsername(test.input)
		if err != test.expected {
			t.Errorf("test %s: returned value is not as expected: %v (actual) != %v (expected)", test.desc, err, test.expected)
		}
	}
}

func TestCreateUserRequest_ValidateUsername_DisallowedCharacters(t *testing.T) {
	disallowedCharacters := " !@#$%^&*()+=';<>?,|\\{}/`~'é立显荣朝士"
	baseName := "user1"

	for _, c := range disallowedCharacters {
		username := fmt.Sprintf("%s%s", baseName, string(c))

		err := ValidateUsername(username)
		if err != ErrInvalidUsername {
			t.Errorf("ValidateUsername did not return an ErrInvalidUsername for %s", username)
		}
	}
}

func TestValidateFullName(t *testing.T) {
	tests := []struct {
		desc     string
		input    string
		expected error
	}{
		{
			desc:     "normal name",
			input:    "Testie McTestface",
			expected: nil,
		},
		{
			desc:     "Greek name",
			input:    "Σum",
			expected: nil,
		},
		{
			desc:     "name with Chinese characters",
			input:    "立显荣朝士",
			expected: nil,
		},
		{
			desc:     "short Chinese name",
			input:    "阿",
			expected: nil,
		},
		{
			desc:     "long name",
			input:    "Adolph Blaine Charles David Earl Frederick Gerald Hubert Irvin John Kenneth Lloyd Martin Nero Oliver Paul",
			expected: nil,
		},
		{
			desc:     "too long name",
			input:    "Adolph Blaine Charles David Earl Frederick Gerald Hubert Irvin John Kenneth Lloyd Martin Nero Oliver Paul Quincy Randolph Sherman Thomas Uncas Victor William Xerxes Yancy Zeus ",
			expected: ErrInvalidFullName,
		},
		{
			desc:     "name with newline",
			input:    "Name\nWith newline",
			expected: ErrInvalidFullName,
		},
		{
			desc:     "name with tab",
			input:    "Name\tWith tab",
			expected: ErrInvalidFullName,
		},
		{
			desc:     "name with a thin space",
			input:    "Testie McTestface",
			expected: ErrInvalidFullName,
		},
		{
			desc:     "empty name",
			input:    "",
			expected: ErrInvalidFullName,
		},
	}

	for _, test := range tests {
		err := ValidateFullName(test.input)
		if err != test.expected {
			t.Errorf("test %s: returned value is not as expected: %v (actual) != %v (expected)", test.desc, err, test.expected)
		}
	}
}

func TestCreateUserRequest_Validate(t *testing.T) {
	cases := map[string]struct {
		req CreateUserRequest
		err error
	}{
		"valid using password": {
			req: CreateUserRequest{
				Username: "test.-_UserTestT",
				Email:    "test-account.dev1@secrethub.io",
				FullName: "Test Tester",
				Password: "hello world",
			},
			err: nil,
		},
		"valid using credential": {
			req: CreateUserRequest{
				Username: "test.-_UserTestT",
				Email:    "test-account.dev1@secrethub.io",
				FullName: "Test Tester",
				Credential: &CreateCredentialRequest{
					Name:        "Personal laptop credential",
					Type:        CredentialTypeRSA,
					Fingerprint: "fingerprint",
					Verifier:    []byte("verifier"),
				},
			},
			err: nil,
		},
		"invalid no password nor credential": {
			req: CreateUserRequest{
				Username: "test.-_UserTestT",
				Email:    "test-account.dev1@secrethub.io",
				FullName: "Test Tester",
			},
			err: ErrNoPasswordNorCredential,
		},
		"invalid username": {
			req: CreateUserRequest{
				Username: "",
				Email:    "test-account.dev1@secrethub.io",
				FullName: "Test Tester",
				Password: "hello world",
			},
			err: ErrInvalidUsername,
		},
		"invalid email": {
			req: CreateUserRequest{
				Username: "test",
				Email:    "notanemail",
				FullName: "Test Tester",
				Password: "hello world",
			},
			err: ErrInvalidEmail,
		},
		"invalid full name": {
			req: CreateUserRequest{
				Username: "test",
				Email:    "test-account.dev1@secrethub.io",
				FullName: "",
				Password: "hello world",
			},
			err: ErrInvalidFullName,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Do
			err := tc.req.Validate()

			// Assert
			testutil.Compare(t, err, tc.err)
		})
	}
}

func TestCreateCredentialRequest_Validate(t *testing.T) {
	cases := map[string]struct {
		req CreateCredentialRequest
		err error
	}{
		"success": {
			req: CreateCredentialRequest{
				Name:        "Personal laptop credential",
				Type:        CredentialTypeRSA,
				Fingerprint: "fingerprint",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"success without name": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeRSA,
				Fingerprint: "fingerprint",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"empty fingerprint": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeRSA,
				Name:        "Personal laptop credential",
				Fingerprint: "",
				Verifier:    []byte("verifier"),
			},
			err: ErrInvalidFingerprint,
		},
		"empty verifier": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeRSA,
				Name:        "Personal laptop credential",
				Fingerprint: "fingerprint",
				Verifier:    []byte(""),
			},
			err: ErrInvalidVerifier,
		},
		"empty algorithm": {
			req: CreateCredentialRequest{
				Name:        "Personal laptop credential",
				Fingerprint: "fingerprint",
				Verifier:    []byte("verifier"),
			},
			err: ErrInvalidAlgorithm,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Do
			err := tc.req.Validate()

			// Assert
			testutil.Compare(t, err, tc.err)
		})
	}
}
