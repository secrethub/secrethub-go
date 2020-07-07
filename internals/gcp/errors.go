package gcp

import (
	"net/http"
	"strings"

	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	gcpErr                = errio.Namespace("gcp")
	ErrGCPAlreadyExists   = gcpErr.Code("already_exists")
	ErrGCPNotFound        = gcpErr.Code("not_found")
	ErrGCPAccessDenied    = gcpErr.Code("access_denied")
	ErrGCPInvalidArgument = gcpErr.Code("invalid_argument")
	ErrGCPUnauthenticated = gcpErr.Code("unauthenticated").Error("missing valid GCP authentication")
)

func HandleError(err error) error {
	errGCP, ok := err.(*googleapi.Error)
	if ok {
		message := errGCP.Message
		switch errGCP.Code {
		case http.StatusNotFound:
			if message == "" {
				message = "404 not found"
			}
			return ErrGCPNotFound.Error(message)
		case http.StatusForbidden:
			if message == "" {
				message = "403 access denied"
			}
			return ErrGCPAccessDenied.Error(message)
		case http.StatusConflict:
			if message == "" {
				message = "409 conflict"
			}
			return ErrGCPAlreadyExists.Error(message)
		}
		if len(errGCP.Errors) > 0 {
			return gcpErr.Code(errGCP.Errors[0].Reason).Error(errGCP.Errors[0].Message)
		}
	}
	errStatus, ok := status.FromError(err)
	if ok {
		msg := strings.TrimSuffix(errStatus.Message(), ".")
		switch errStatus.Code() {
		case codes.InvalidArgument:
			return ErrGCPInvalidArgument.Error(msg)
		case codes.NotFound:
			return ErrGCPNotFound.Error(msg)
		case codes.PermissionDenied:
			return ErrGCPAccessDenied.Error(msg)
		case codes.Unauthenticated:
			return ErrGCPUnauthenticated
		}
	}
	return err
}
