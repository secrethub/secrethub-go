package auth

import "net/http"

type NopAuthenticator struct{}

func (s NopAuthenticator) Authenticate(r *http.Request) error {
	return nil
}
