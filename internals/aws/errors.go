package aws

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	awsErr                  = errio.Namespace("aws")
	ErrNoAWSCredentials     = awsErr.Code("no_aws_credentials").Error("could not find any AWS credentials. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html for how to configure your credentials")
	ErrInvalidAWSCredential = awsErr.Code("invalid_credential").Error("credentials were not accepted by AWS")
	ErrAWSRequestError      = awsErr.Code("request_error").Error("could not send AWS request")
	ErrAWSNotFound          = awsErr.Code("not_found")
	ErrAWSAccessDenied      = awsErr.Code("access_denied")
)

func handleError(err error) error {
	errAWS, ok := err.(awserr.Error)
	if ok {
		switch errAWS.Code() {
		case "NoCredentialProviders", "MissingAuthenticationToken", "MissingAuthenticationTokenException":
			return ErrNoAWSCredentials
		case "UnrecognizedClientException", "InvalidClientTokenId":
			return ErrInvalidAWSCredential
		case "RequestError":
			return ErrAWSRequestError
		case "AccessDeniedException":
			return ErrAWSAccessDenied.Error(errAWS.Message())
		case "NotFoundException":
			return ErrAWSNotFound.Error(errAWS.Message())
		}

		return awsErr.Code(errAWS.Code()).Error(errAWS.Message())
	}
	return err
}
