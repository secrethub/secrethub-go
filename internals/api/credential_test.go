package api

import (
	"github.com/secrethub/secrethub-go/internals/assert"
	"testing"
)

func TestCreateCredentialRequest_Validate(t *testing.T) {
	cases := map[string]struct {
		req CreateCredentialRequest
		err error
	}{
		"success": {
			req: CreateCredentialRequest{
				Name:        "Personal laptop credential",
				Type:        CredentialTypeRSA,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"success without name": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeRSA,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"no fingerprint": {
			req: CreateCredentialRequest{
				Type:     CredentialTypeRSA,
				Name:     "Personal laptop credential",
				Verifier: []byte("verifier"),
			},
			err: ErrMissingField("fingerprint"),
		},
		"invalid fingerprint": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeRSA,
				Name:        "Personal laptop credential",
				Fingerprint: "not-valid",
				Verifier:    []byte("verifier"),
			},
			err: ErrInvalidFingerprint,
		},
		"empty verifier": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeRSA,
				Name:        "Personal laptop credential",
				Fingerprint: "fingerprint",
				Verifier:    nil,
			},
			err: ErrMissingField("verifier"),
		},
		"empty type": {
			req: CreateCredentialRequest{
				Name:        "Personal laptop credential",
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: ErrMissingField("type"),
		},
		"invalid type": {
			req: CreateCredentialRequest{
				Name:        "Personal laptop credential",
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
				Type:        CredentialType("invalid"),
			},
			err: ErrInvalidCredentialType,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Do
			err := tc.req.Validate()

			// Assert
			assert.Equal(t, err, tc.err)
		})
	}
}
