package oauthorizer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/secrethub/secrethub-go/pkg/randchar"
)

type CallbackHandler struct {
	authorizer Authorizer
	listener   net.Listener
	state      string

	baseRedirectURL *url.URL

	errChan chan error
}

func NewCallbackHandler(redirectURL *url.URL, authorizer Authorizer) (CallbackHandler, error) {
	state, err := randchar.Generate(20)
	if err != nil {
		return CallbackHandler{}, fmt.Errorf("generating random state: %s", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return CallbackHandler{}, err
	}

	return CallbackHandler{
		authorizer:      authorizer,
		baseRedirectURL: redirectURL,
		listener:        l,
		state:           string(state),
		errChan:         make(chan error, 1),
	}, nil
}

func (s CallbackHandler) ListenURL() string {
	return "http://" + s.listener.Addr().String()
}

func (s CallbackHandler) AuthorizeURL() string {
	return s.authorizer.AuthorizeLink(s.ListenURL(), s.state)
}

// WithAuthorizationCode executes the provided function with the resulting authorization code or error.
// Afterwards the user is redirected to the CallbackHandler's baseRedirectURL. If the callback produced an error,
// the error is appended to the redirect url: &error=<error>.
// The provided callback function will only be executed once, even if multiple successful callbacks arrive at the server.
// This function returns when the callback has been executed and the user is redirected.
func (s CallbackHandler) WithAuthorizationCode(callback func(string, error) error) error {
	defer s.listener.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s.errChan <- http.Serve(s.listener, http.HandlerFunc(s.handleRequest(callback, cancel)))
		cancel()
	}()

	<-ctx.Done()

	select {
	case err := <-s.errChan:
		return err
	default:
		return nil
	}
}

func (s CallbackHandler) handleRequest(callback func(string, error) error, done func()) func(w http.ResponseWriter, r *http.Request) {
	var once sync.Once
	var redirectURL *url.URL
	return func(w http.ResponseWriter, r *http.Request) {
		code, err := s.authorizer.ParseResponse(r, s.state)
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err)
			return
		}

		once.Do(func() {
			err = callback(code, err)
			redirectURL = s.baseRedirectURL
			if err != nil {
				q := redirectURL.Query()
				q.Set("error", err.Error())
				redirectURL.RawQuery = q.Encode()
				s.errChan <- err
			}
		})

		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
		done()
	}
}
