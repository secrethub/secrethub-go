package credentials

import (
	"fmt"
	"net/http"

	httpclient "github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"

	"github.com/secrethub/secrethub-go/internals/auth"
)

type SetupCode struct {
	code string
}

func (s *SetupCode) Provide(client *httpclient.Client) (auth.Authenticator, Decrypter, error) {
	return s, nil, nil
}

func NewSetupCode(code string) *SetupCode {
	return &SetupCode{
		code: code,
	}
}

// Authenticate authenticates the given request with a setup code, by providing the "SetupCode" tag and the setup code
// in the "Authorization" header.
func (s *SetupCode) Authenticate(r *http.Request) error {
	r.Header.Set("Authorization", fmt.Sprintf("%s-%s %s", auth.AuthHeaderVersionV1, "SetupCode", s.code))
	return nil
}
