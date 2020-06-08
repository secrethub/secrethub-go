package credentials

import (
	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials/sessions"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// UseAWS returns a Provider that can be used to use an assumed AWS role as a credential for SecretHub.
// The provided awsCfg is used to configure the AWS client.
// If used on AWS (e.g. from an EC2-instance), this extra configuration is not required and the correct configuration
// should be auto-detected by the AWS client.
//
// Usage:
//		credentials.UseAWS()
//		credentials.UseAWS(&aws.Config{Region: aws.String("eu-west-1")})
func UseAWS(awsCfg ...*awssdk.Config) Provider {
	return providerFunc(func(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		authenticator := sessions.NewSessionRefresher(httpClient, sessions.NewAWSSessionCreator(awsCfg...))
		return authenticator, decrypter, nil
	})
}

// CreateAWS returns a Creator that creates an AWS-based credential.
// The kmsKeyID is the ID of the key in KMS that is used to encrypt the account key.
// The roleARN is for the IAM role that should be assumed to use this credential.
// The role should have decryption permission on the provided KMS key.
// awsCfg can be used to optionally configure the used AWS client. For example to set the region.
// The KMS key id and role are returned in the credentials metadata.
func CreateAWS(kmsKeyID string, roleARN string, awsCfg ...*awssdk.Config) Creator {
	return &awsCreator{
		kmsKeyID: kmsKeyID,
		roleARN:  roleARN,
		awsCfg:   awsCfg,
	}
}

type awsCreator struct {
	kmsKeyID string
	roleARN  string
	awsCfg   []*awssdk.Config

	credentialCreator *aws.CredentialCreator
	metadata          map[string]string
}

func (ac *awsCreator) Create() error {
	creator, metadata, err := aws.NewCredentialCreator(ac.kmsKeyID, ac.roleARN, ac.awsCfg...)
	if err != nil {
		return err
	}
	ac.credentialCreator = creator
	ac.metadata = metadata
	return nil
}

func (ac *awsCreator) Verifier() Verifier {
	return ac.credentialCreator
}

func (ac *awsCreator) Encrypter() Encrypter {
	return ac.credentialCreator
}

func (ac *awsCreator) Metadata() map[string]string {
	return ac.metadata
}
