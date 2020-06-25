package oauthorizer

import (
	"fmt"
	"net"
	"net/http"

	"github.com/secrethub/secrethub-go/pkg/randchar"
)

type CallbackHandler struct {
	authorizer Authorizer
	listener   net.Listener
	state      string

	resChan chan result
}

type result struct {
	err               error
	authorizationCode string
}

func NewCallbackHandler(authorizer Authorizer) (CallbackHandler, error) {
	state, err := randchar.Generate(20)
	if err != nil {
		return CallbackHandler{}, fmt.Errorf("generating random state: %s", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return CallbackHandler{}, err
	}

	return CallbackHandler{
		authorizer: authorizer,
		listener:   l,
		state:      string(state),
		resChan:    make(chan result, 1),
	}, nil
}

func (s CallbackHandler) ListenURL() string {
	return "http://" + s.listener.Addr().String()
}

func (s CallbackHandler) AuthorizeURL() string {
	return s.authorizer.AuthorizeLink(s.ListenURL(), s.state)
}

func (s CallbackHandler) WaitForAuthorizationCode() (string, error) {
	defer s.listener.Close()

	errChan := make(chan error, 1)
	go func() {
		errChan <- http.Serve(s.listener, http.HandlerFunc(s.handleRequest))
	}()

	select {
	case err := <-errChan:
		return "", err
	case res := <-s.resChan:
		return res.authorizationCode, res.err
	}
}

func (s CallbackHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	code, err := s.authorizer.ParseResponse(r, s.state)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	} else {
		fmt.Fprint(w, "Authorization complete. You can now close this tab")
	}
	select {
	case s.resChan <- result{
		err:               err,
		authorizationCode: code,
	}:
	default:
	}
}
