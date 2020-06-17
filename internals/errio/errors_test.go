package errio

import (
	"encoding/json"
	go_errors "errors"
	"reflect"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
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

func TestEquals(t *testing.T) {
	cases := map[string]struct {
		a        PublicError
		b        error
		expected bool
	}{
		"completely equal errors": {
			a:        Namespace("app").Code("invalid foo").Error("invalid value for foo: value should be a string"),
			b:        Namespace("app").Code("invalid foo").Error("invalid value for foo: value should be a string"),
			expected: true,
		},
		"different error message": {
			a:        Namespace("app").Code("invalid value").Error("invalid value for foo: value should be a string"),
			b:        Namespace("app").Code("invalid value").Error("invalid value for foo: value cannot contain special characters"),
			expected: true,
		},
		"different namespace": {
			a:        Namespace("app").Code("invalid foo").Error("invalid value for foo: value should be a string"),
			b:        Namespace("foo").Code("invalid foo").Error("invalid value for foo: value should be a string"),
			expected: false,
		},
		"different code": {
			a:        Namespace("app").Code("invalid foo").Error("invalid value for foo: value should be a string"),
			b:        Namespace("app").Code("unauthenticated").Error("request is not authenticated"),
			expected: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := Equals(tc.a, tc.b)

			assert.Equal(t, actual, tc.expected)
		})
	}
}
