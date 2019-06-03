package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// Errors
var (
	ErrUnsupportedSignMethod = errNamespace.Code("unsupported_sign_method").StatusError("the sign method in the authorization header is not supported", http.StatusBadRequest)
	ErrUnsupportedAuthFormat = errNamespace.Code("unsupported_auth_format").StatusError("the authentication format in the Authorization header is not supported", http.StatusBadRequest)
	ErrNoAuthHeader          = errNamespace.Code("no_auth_header").StatusError("the authorization header should be set", http.StatusBadRequest)
)

// Verifier can authenticate an account from an http request.
type Verifier interface {
	Verify(r *http.Request) (*Result, error)
}

// CredentialAuthenticator authenticates an account from credentials and signed data.
type CredentialAuthenticator interface {
	Verify(credentials string, data []byte) (*Result, error)
}

// NewVerifier returns a new Verifier, supporting the given Methods.
func NewVerifier(methods ...Method) Verifier {
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
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoAuthHeader
	}

	format := strings.SplitN(authHeader, " ", 2)
	if len(format) != 2 {
		return nil, ErrUnsupportedAuthFormat
	}

	if format[0] == MethodTagSignatureV1 || format[0] == MethodTagSignatureV2 {
		return nil, ErrOutdatedSignatureProtocol
	}

	method, ok := a.methods[format[0]]
	if !ok {
		return nil, ErrUnsupportedAuthFormat
	}

	requestTime, err := time.Parse(time.RFC1123, r.Header.Get("Date"))
	if err != nil {
		return nil, ErrCannotParseDateHeader
	}

	err = isTimeValid(requestTime, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	message, err := getMessage(r)
	if err != nil {
		return nil, err
	}

	return method.Verify(format[1], message)
}

// Method defines a mechanism to authenticate an account from an http.Request.
type Method interface {
	CredentialAuthenticator
	// Tag returns the authorization header tag identifying the authentication mechanism.
	Tag() string
}

// Result is the result object returned on an Authenticate method call.
type Result struct {
	AccountID   *uuid.UUID
	Fingerprint string
}
