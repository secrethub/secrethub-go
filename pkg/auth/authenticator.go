package auth

import (
	"net/http"
	"strings"

	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
)

// Errors
var (
	ErrUnsupportedAuthFormat = errNamespace.Code("unsupported_auth_format").StatusError("the authentication format in the Authorization header is not supported", http.StatusBadRequest)
	ErrNoAuthHeader          = errNamespace.Code("no_auth_header").StatusError("the authorization header should be set", http.StatusBadRequest)
)

// Authenticator can authenticate an account from an http request.
type Authenticator interface {
	Verify(r *http.Request) (*Result, error)
}

// NewAuthenticator returns a new Authenticator, supporting the given Methods.
func NewAuthenticator(methods ...Method) Authenticator {
	a := &authenticator{
		methods: make(map[string]Method),
	}

	for _, m := range methods {
		a.methods[m.Tag()] = m
	}

	return a
}

// authenticator supports one or more methods for authenticating an account from HTTP requests.
type authenticator struct {
	methods map[string]Method
}

// Verify verifies the authentication of an HTTP request.
func (a *authenticator) Verify(r *http.Request) (*Result, error) {
	method, err := a.getMethod(r)
	if err != nil {
		return nil, err
	}
	return method.Verify(r)
}

func (a *authenticator) getMethod(r *http.Request) (Method, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoAuthHeader
	}

	format := strings.SplitN(authHeader, " ", 2)
	if len(format) != 2 {
		return nil, ErrUnsupportedAuthFormat
	}

	method, ok := a.methods[format[0]]
	if !ok {
		return nil, ErrUnsupportedAuthFormat
	}
	return method, nil
}

// Method defines a mechanism to authenticate an account from an http.Request.
type Method interface {
	Authenticator
	// Tag returns the authorization header tag identifying the authentication mechanism.
	Tag() string
}

// Result is the result object returned on an Authenticate method call.
type Result struct {
	AccountID   *uuid.UUID
	Fingerprint string
}
