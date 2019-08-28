package secrethub

import (
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi"

	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

var (
	cred1            *credentials.RSACredential
	cred1PublicKey   []byte
	cred1Fingerprint string
	cred1Verifier    []byte
)

func init() {
	var err error
	cred1, err = credentials.GenerateRSACredential(1024)
	if err != nil {
		panic(err)
	}

	cred1PublicKey, err = cred1.Public().Encode()
	if err != nil {
		panic(err)
	}

	cred1Verifier, cred1Fingerprint, err = cred1.Export()
	if err != nil {
		panic(err)
	}
}

// setup starts a test server and returns a router on which tests can register handlers.
// Tests should use the returned client options to create new Clients and should call the
// cleanup func() when done.
func setup() (chi.Router, []ClientOption, func()) {
	// router is the HTTP router used with the test server.
	router := chi.NewRouter()

	// Strip prefixes so tests can register routes on e.g. /users instead of /v1/users.
	handler := http.NewServeMux()
	handler.Handle("/v1/", http.StripPrefix("/v1", router))

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(handler)

	opts := []ClientOption{
		WithServerURL(server.URL),
		WithCredentials(cred1),
	}

	return router, opts, server.Close
}
