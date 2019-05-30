package auth

import (
	"net/http"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

type fakeMethod struct{}

func (m *fakeMethod) Verify(r *http.Request) (*Result, error) {
	return nil, nil
}

func (m *fakeMethod) Tag() string {
	return "TestAuth"
}

func TestAuthenticator_GetMethod(t *testing.T) {

	cases := map[string]struct {
		request http.Request
		err     error
	}{
		"no header": {
			http.Request{},
			ErrNoAuthHeader,
		},
		"empty header": {
			http.Request{
				Header: map[string][]string{
					"Authorization": {""},
				},
			},
			ErrNoAuthHeader,
		},
		"no key or token": {
			http.Request{
				Header: map[string][]string{
					"Authorization": {"TestAuth"},
				},
			},
			ErrUnsupportedAuthFormat,
		},
		"success": {
			http.Request{
				Header: map[string][]string{
					"Authorization": {"TestAuth token"},
				},
			},
			nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {

			authenticator := &authenticator{
				methods: map[string]Method{
					"TestAuth": &fakeMethod{},
				},
			}

			res, err := authenticator.getMethod(&tc.request)
			assert.Equal(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, res, &fakeMethod{})
			}
		})
	}
}
