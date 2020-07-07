package oauthorizer

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Authorizer interface {
	AuthorizeLink(redirectURI string, state string) string
	ParseResponse(r *http.Request, state string) (string, error)
}

func NewAuthorizer(authURI, clientID string, scopes ...string) Authorizer {
	return authorizer{
		AuthURI:  authURI,
		ClientID: clientID,
		Scopes:   scopes,
	}
}

type authorizer struct {
	AuthURI  string
	ClientID string
	Scopes   []string
}

func (a authorizer) AuthorizeLink(redirectURI string, state string) string {
	return fmt.Sprintf(`%s?`+
		`scope=%s&`+
		`access_type=online&`+
		`response_type=code&`+
		`redirect_uri=%s&`+
		`state=%s&`+
		`prompt=select_account&`+
		`client_id=%s`,
		a.AuthURI,
		url.QueryEscape(strings.Join(a.Scopes, ",")),
		url.QueryEscape(redirectURI),
		state,
		a.ClientID,
	)
}

func (a authorizer) ParseResponse(r *http.Request, expectedState string) (string, error) {
	errorMessage := r.URL.Query().Get("error")
	if errorMessage != "" {
		return "", fmt.Errorf("authorization error: %s", errorMessage)
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		return "", errors.New("missing state query parameter")
	}
	if state != expectedState {
		return "", errors.New("state does not match")
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", errors.New("missing code query parameter")
	}
	return code, nil
}
