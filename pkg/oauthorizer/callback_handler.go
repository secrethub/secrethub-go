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

	resChan chan string
	errChan chan error
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
		resChan:    make(chan string),
		errChan:    make(chan error),
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

	go func() {
		err := http.Serve(s.listener, http.HandlerFunc(s.handleRequest))
		if err != nil && err != http.ErrServerClosed {
			s.errChan <- err
		}
	}()

	select {
	case err := <-s.errChan:
		return "", err
	case res := <-s.resChan:
		return res, nil
	}
}

func (s CallbackHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	code, err := s.authorizer.ParseResponse(r, s.state)
	if err != nil {
		s.errChan <- err
		fmt.Fprintf(w, "Error: %s", err)
	} else {
		s.resChan <- code
		fmt.Fprint(w, "Authorization complete. You can now close this tab")
	}
}
