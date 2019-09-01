package http

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	ErrWrongContentType = errHTTP.Code("wrong_content_type").Error("server returned wrong content type in header")
)

// validator is an interface that helps validate the values of arguments.
type validator interface {
	Validate() error
}

// encodeRequest simplifies setting the request body and correct headers.
// If in == nil, nothing happens, else it will attempt to encode the body as json.
// Before encoding, it will validate the input if possible.
func encodeRequest(req *http.Request, in interface{}) error {
	if in == nil {
		return nil
	}

	validator, ok := in.(validator)
	if ok {
		err := validator.Validate()
		if err != nil {
			return errio.StatusError(err)
		}
	}

	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return errHTTP.Code("cannot_encode_request").StatusErrorf("cannot encode request: %v", http.StatusBadRequest, err)
	}

	buf := bytes.NewBuffer(jsonBytes)
	req.Body = ioutil.NopCloser(buf)

	req.ContentLength = int64(len(jsonBytes))
	req.Header.Set("Content-Length", strconv.Itoa(len(jsonBytes)))
	req.Header.Set("Content-Type", "application/json")

	return nil
}

// decodeResponse reads the response body and checks for the correct headers.
// If out == nil, nothing happens, else it will attempt to decode the body as json.
// After decoding, it will validate the result if possible.
func decodeResponse(resp *http.Response, out interface{}) error {
	if out == nil {
		return nil
	}

	if t := resp.Header.Get("Content-Type"); t != "application/json" {
		return ErrWrongContentType
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errio.StatusError(err)
	}

	err = json.Unmarshal(bytes, out)
	if err != nil {
		return errHTTP.Code("cannot_decode_response").StatusErrorf("cannot decode response: %v", http.StatusInternalServerError, err)
	}

	validator, ok := out.(validator)
	if ok {
		err := validator.Validate()
		if err != nil {
			return errio.StatusError(err)
		}
	}
	return nil
}

// parseError parses the body of an http.Response into an errio.PublicStatusError.
// If unsuccessful, it simply outputs the statuscode and the bytes of the body.
func parseError(resp *http.Response) error {
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errHTTP.Code("cannot_read_response").Errorf("cannot read the server response: %s", err)
	}

	// Try to unmarshal into a PublicStatusError
	e := errio.PublicStatusError{}
	err = json.Unmarshal(bytes, &e)
	if err != nil {
		// Degrade with a best effort error message.
		log.Debugf("body: %v", string(bytes))
		return errHTTP.Code("cannot_parse_server_response").Errorf("%d - %s: %v",
			resp.StatusCode,
			resp.Status,
			err,
		)
	}
	if e.Message == "" {
		return errHTTP.Code("unexpected_message_in_server_error").Errorf("%d - %s. Response:\n%s",
			resp.StatusCode,
			resp.Status,
			string(bytes),
		)
	}

	e.StatusCode = resp.StatusCode
	return e
}
