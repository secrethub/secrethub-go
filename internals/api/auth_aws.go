package api

import "net/http"

// Errors
var (
	ErrCouldNotGetEndpoint   = errAPI.Code("aws_endpoint_not_found").StatusError("could not find an AWS endpoint for the provided region", http.StatusBadRequest)
	ErrAWSException          = errAPI.Code("aws_exception").StatusError("encountered an unexpected problem while verifying your identity on AWS. Please try again later.", http.StatusFailedDependency)
	ErrNoServiceWithRole     = errAPI.Code("no_service_with_role").StatusErrorPref("no service account found that is linked to the IAM role '%s'", http.StatusNotFound)
	ErrNoAWSCredentials      = errAPI.Code("missing_aws_credentials").StatusError("request was not signed with AWS credentials", http.StatusUnauthorized)
	ErrInvalidAWSCredentials = errAPI.Code("invalid_aws_credentials").StatusError("credentials were not accepted by AWS", http.StatusUnauthorized)
)

// AuthPayloadAWSSTS is the authentication payload used for authenticating with AWS STS.
type AuthPayloadAWSSTS struct {
	Region  string `json:"region"`
	Request []byte `json:"request"`
}

// NewAuthRequestAWSSTS returns a new AuthRequest for authentication using AWS STS.
func NewAuthRequestAWSSTS(sessionType SessionType, region string, stsRequest []byte) AuthRequest {
	return AuthRequest{
		Method:      AuthMethodAWSSTS,
		SessionType: sessionType,
		Payload: &AuthPayloadAWSSTS{
			Region:  region,
			Request: stsRequest,
		},
	}
}

// Validate whether the AuthPayloadAWSSTS is valid.
func (pl AuthPayloadAWSSTS) Validate() error {
	if pl.Region == "" {
		return ErrMissingField("region")
	}
	if pl.Request == nil {
		return ErrMissingField("request")
	}
	return nil
}
