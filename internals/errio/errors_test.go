package errio

import (
	"encoding/json"
	go_errors "errors"
	"net/http"
	"reflect"
	"testing"
)

var (
	testError = PublicStatusError{
		PublicError: PublicError{
			Code:    "test",
			Message: "some test error",
		},
	}
	data         = []byte(`{"error":{"code":"test","message":"some test error"}}`)
	errorMessage = "test_error"
)

func TestMarshal(t *testing.T) {
	bytes, err := json.Marshal(testError)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(bytes, data) {
		t.Errorf("unexpected bytes:\n\t %v (actual) != %v (expected)", bytes, data)
	}
}

func TestUnmarshal(t *testing.T) {
	e := PublicStatusError{}
	err := json.Unmarshal(data, &e)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(e, testError) {
		t.Errorf("unexpected value:\n\t%v (actual) != %v (expected)", e, testError)
	}
}

func TestExpectedError(t *testing.T) {
	expectedMsg := "This is a test error"
	expectedNs := "test"
	expectedCode := "test_code"

	ns := Namespace(expectedNs)
	err := ns.Code(expectedCode).Errorf("This is a test %s", "error")

	parsedErr := Error(err)

	if !isPublicError(parsedErr) {
		t.Error("did not return a PublicError")
	}

	customError := parsedErr.(PublicError)

	if customError.Message != expectedMsg {
		t.Errorf("error dit not contain the correct message, %s (actual) != %s (expected)", customError.Message, expectedMsg)
	}

	if customError.Code != expectedCode {
		t.Errorf("error dit not contain the correct code, %s (actual) != %s (expected)", customError.Code, expectedCode)
	}

	if string(customError.Namespace) != expectedNs {
		t.Errorf("error dit not contain the correct namespace, %s (actual) != %s (expected)", customError.Namespace, expectedNs)
	}
}

func TestUnexpectedError(t *testing.T) {
	unexpected := go_errors.New(errorMessage)
	err := Error(unexpected)

	if !isPublicError(err) {
		t.Error("did not return a PublicError")
	}

	customError := err.(PublicError)

	if customError.Code != "unexpected" {
		t.Errorf("did not return correct code expected: `unexpected`, actual: %s", customError.Code)
	}

	if len(customError.Message) == 0 {
		t.Error("returned error does not contain a message")
	}
}

func TestUnexpectedStatusError(t *testing.T) {
	unexpected := go_errors.New(errorMessage)
	err := StatusError(unexpected)

	if !isPublicStatusError(err) {
		t.Error("did not return a PublicStatusError")
	}

	statusError := err.(PublicStatusError)

	if statusError.Code != "unexpected" {
		t.Errorf("did not return correct code expected: `unexpected`, actual: %s", statusError.Code)
	}

	if statusError.StatusCode != http.StatusInternalServerError {
		t.Errorf("did not return correct StatusCode, expected: %d, actual: %d", http.StatusInternalServerError, statusError.StatusCode)
	}

	if len(statusError.Message) == 0 {
		t.Error("returned error does not contain a message")
	}
}
