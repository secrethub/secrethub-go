// Package errio contains custom error types to easily transfer errors
// between applications and output them to the user in a consistent way.
package errio

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("log")
)

// Namespace is a container for different errors and is
// used to distinguish between error codes. Using different
// namespaces helps you to keep error codes unique throughout
// your codebase. Typically, namespaces will carry the name of
// their package name or file name (without the .go part).
type Namespace string

// ErrorCode contains a code that should be unique to the namespace it belongs to
type ErrorCode struct {
	Code      string
	Namespace Namespace
}

// Code returns a new ErrorCode
func (n Namespace) Code(code string) ErrorCode {
	return ErrorCode{
		Code:      code,
		Namespace: n,
	}
}

// StatusError creates a new PublicStatusError
func (c ErrorCode) StatusError(message string, status int) PublicStatusError {
	return PublicStatusError{
		StatusCode: status,
		PublicError: PublicError{
			Namespace: c.Namespace,
			Code:      c.Code,
			Message:   message,
		},
	}
}

// StatusErrorf works like fmt.Errorf to create a StatusError
func (c ErrorCode) StatusErrorf(message string, status int, args ...interface{}) PublicStatusError {
	return c.StatusError(fmt.Sprintf(message, args...), status)
}

// StatusErrorPref returns a function that can be called with arguments to create a formatted status error message
func (c ErrorCode) StatusErrorPref(message string, status int) func(args ...interface{}) PublicStatusError {
	return func(args ...interface{}) PublicStatusError {
		return PublicStatusError{
			StatusCode: status,
			PublicError: PublicError{
				Namespace: c.Namespace,
				Code:      c.Code,
				Message:   fmt.Sprintf(message, args...),
			},
		}
	}
}

// Error returns a PublicError with the given code and message
func (c ErrorCode) Error(message string) PublicError {
	return PublicError{
		Namespace: c.Namespace,
		Code:      c.Code,
		Message:   message,
	}
}

// Errorf works like fmt.Errorf to create an Error.
func (c ErrorCode) Errorf(message string, args ...interface{}) PublicError {
	return c.Error(fmt.Sprintf(message, args...))
}

// ErrorPref returns a function that can be called with arguments to create a formatted error message
func (c ErrorCode) ErrorPref(message string) func(args ...interface{}) PublicError {
	return func(args ...interface{}) PublicError {
		return PublicError{
			Namespace: c.Namespace,
			Code:      c.Code,
			Message:   fmt.Sprintf(message, args...),
		}
	}
}

// StatusError can be called to on any error to convert it to a PublicStatusError if it is not already.
// If it is not yet a PublicError, an UnexpectedError is returned
func StatusError(err error) error {
	if err == nil {
		return nil
	}

	if isPublicStatusError(err) {
		return err
	}

	return UnexpectedStatusError(err)
}

// Error returns the inputted error.
// Deprecated: this leads to unwanted returns of UnexpectedErrrors and should therefor not be used anymore.
func Error(err error) error {
	return err
}

// IsKnown checks whether the given error is known.
func IsKnown(err error) bool {
	return isPublicError(err) || isPublicStatusError(err)
}

// isPublicError checks if an error is of type PublicError
func isPublicError(err error) bool {
	_, ok := err.(PublicError)
	return ok
}

// isPublicStatusError checks if an error is of type PublicStatusError
func isPublicStatusError(err error) bool {
	_, ok := err.(PublicStatusError)
	return ok
}

// UnexpectedError represents an error that we did not expect.
// Unexpected errors are reported and logged.
func UnexpectedError(err error) PublicError {
	if isPublicStatusError(err) {
		return err.(PublicStatusError).PublicError
	}
	if isPublicError(err) {
		return err.(PublicError)
	}

	// Log the eventID and stack trace for debugging.
	log.Debugf(
		"An unexpected error occurred: %v\nStack Trace:%s",
		err,
		string(debug.Stack()),
	)

	return PublicError{
		Code: "unexpected",
		Message: fmt.Sprintf(
			"an unexpected error occurred: %v\n\nTry again later or contact support@secrethub.io if the problem persists",
			err,
		),
	}
}

// UnexpectedStatusError is an error we did not expect, with http.StatusInternalServerError attached to it.
func UnexpectedStatusError(err error) PublicStatusError {
	if isPublicStatusError(err) {
		return err.(PublicStatusError)
	}
	// Log the eventID and stack trace for debugging.
	log.Debugf(
		"An unexpected error occurred: %v\nStack Trace:%s",
		err,
		string(debug.Stack()),
	)

	return PublicStatusError{
		PublicError: PublicError{
			Code: "unexpected",
			Message: fmt.Sprintf(
				"an unexpected server error occurred. Try again later or contact support@secrethub.io if the problem persists",
			),
		},
		StatusCode: http.StatusInternalServerError,
	}
}

// PublicError is a wrapper around an error code and a error message.
// This allows clear error messaging and trace ability.
type PublicError struct {
	Namespace Namespace `json:"namespace,omitempty"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
}

// PublicError implements the error interface.
func (e PublicError) Error() string {
	code := e.Code
	if e.Namespace != "" {
		code = fmt.Sprintf("%s.%s", e.Namespace, e.Code)
	}
	return fmt.Sprintf("%s (%s) ", e.Message, code)
}

// Append appends multiple errors to an PublicError.
func (e PublicError) Append(errs ...error) PublicError {
	message := e.Message

	for _, err := range errs {
		message = fmt.Sprintf("%s: %s", err.Error(), message)
	}

	return PublicError{
		Namespace: e.Namespace,
		Code:      e.Code,
		Message:   message,
	}
}

// Type returns the type of the error as to be reported to Sentry.
func (e PublicError) Type() string {
	return fmt.Sprintf("%s.%s", e.Namespace, e.Code)
}

// PublicStatusError represents an http error. It contains an HTTP status
// code and can be json encoded in an HTTP response.
type PublicStatusError struct {
	PublicError `json:"error"`
	StatusCode  int `json:"-"`
}

// Error implements the error interface.
func (e PublicStatusError) Error() string {
	return e.PublicError.Error()
}

// Append appends multiple errors to a PublicStatusError
func (e PublicStatusError) Append(errs ...error) PublicStatusError {
	return PublicStatusError{
		PublicError: e.PublicError.Append(errs...),
		StatusCode:  e.StatusCode,
	}
}

// Type returns the type of the error as to be reported to Sentry.
func (e PublicStatusError) Type() string {
	return fmt.Sprintf("%s.%s", e.Namespace, e.Code)
}

// Wrap wraps multiple errors with a PublicStatusError.
func Wrap(base PublicStatusError, errs ...error) PublicStatusError {
	for _, err := range errs {
		base.Message = fmt.Sprintf("%s: %s", base.Message, err.Error())
	}

	return base
}

// Equals returns whether the errors have matching namespace and code.
func Equals(a PublicError, b error) bool {
	publicError, ok := b.(PublicError)
	if !ok {
		return false
	}
	return a.Namespace == publicError.Namespace && a.Code == publicError.Code
}
