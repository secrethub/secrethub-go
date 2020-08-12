package credentials

import (
	"fmt"
	"net/http"

	"github.com/secrethub/secrethub-go/internals/auth"
)

type SetupCode struct {
	code string
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
