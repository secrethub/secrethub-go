package secrethub

import (
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi"
)

var (
	cred1            *RSACredential
	cred1PublicKey   []byte
	cred1Fingerprint string
	cred1Verifier    []byte
)

func init() {
	var err error
	cred1, err = generateRSACredential(1024)
	if err != nil {
		panic(err)
	}

	cred1PublicKey, err = cred1.Public().Export()
	if err != nil {
		panic(err)
	}

	cred1Fingerprint, err = cred1.Fingerprint()
	if err != nil {
		panic(err)
	}

	cred1Verifier, err = cred1.Verifier()
	if err != nil {
		panic(err)
	}
}

// setup starts a test server and returns a router on which tests can register handlers.
// Tests should use the returned client options to create new Clients and should call the
// cleanup func() when done.
func setup() (chi.Router, *ClientOptions, func()) {
	// router is the HTTP router used with the test server.
	router := chi.NewRouter()

	// Strip prefixes so tests can register routes on e.g. /users instead of /v1/users.
	handler := http.NewServeMux()
	handler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, router))

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(handler)

	opts := &ClientOptions{
		ServerURL: server.URL,
	}

	return router, opts, server.Close
}
