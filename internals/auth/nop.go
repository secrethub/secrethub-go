package auth

import "net/http"

// NopAuthenticator is an authenticator that does not add any authentication to the request.
type NopAuthenticator struct{}

// Authenticate the provided request.
func (s NopAuthenticator) Authenticate(r *http.Request) error {
	return nil
}
