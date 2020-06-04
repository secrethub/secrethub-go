package gcp

import (
	"net/http"

	"google.golang.org/api/googleapi"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	gcpErr              = errio.Namespace("gcp")
	ErrGCPAlreadyExists = gcpErr.Code("already_exists")
	ErrGCPNotFound      = gcpErr.Code("not_found")
	ErrGCPAccessDenied  = gcpErr.Code("access_denied")
)

func HandleError(err error) error {
	errGCP, ok := err.(*googleapi.Error)
	if ok {
		switch errGCP.Code {
		case http.StatusNotFound:
			return ErrGCPNotFound.Error(errGCP.Message)
		case http.StatusForbidden:
			return ErrGCPAccessDenied.Error(errGCP.Message)
		case http.StatusConflict:
			return ErrGCPAlreadyExists.Error(errGCP.Message)
		}
		if len(errGCP.Errors) > 0 {
			return gcpErr.Code(errGCP.Errors[0].Reason).Error(errGCP.Errors[0].Message)
		}
	}
	return err
}
