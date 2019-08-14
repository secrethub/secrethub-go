package credentials

import (
	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

func AWS(awsCfg ...*awssdk.Config) secrethub.CredentialProvider {
	return func(client *secrethub.Client) (auth.Authenticator, secrethub.Decrypter, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		authenticator, err := client.Sessions().AWS(awsCfg...).Create()
		if err != nil {
			return nil, nil, err
		}
		return authenticator, decrypter, nil
	}
}

func RSA(credential *secrethub.RSACredential) secrethub.CredentialProvider {
	return func(client *secrethub.Client) (auth.Authenticator, secrethub.Decrypter, error) {
		return auth.NewHTTPSigner(credential), credential, nil
	}
}
