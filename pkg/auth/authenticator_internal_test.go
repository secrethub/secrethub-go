package auth

import (
	"net/http"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/testutil"
)

type fakeMethod struct{}

func (m *fakeMethod) Verify(r *http.Request) (*Result, error) {
	return nil, nil
}

func (m *fakeMethod) Tag() string {
	return "TestAuth"
}

func TestAuthenticator_GetMethod(t *testing.T) {
	testutil.Unit(t)

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
			testutil.Compare(t, err, tc.err)
			if tc.err == nil {
				testutil.Compare(t, res, &fakeMethod{})
			}
		})
	}
}
