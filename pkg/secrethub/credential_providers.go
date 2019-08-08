package secrethub

import (
	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
)

func AWS(awsCfg ...*awssdk.Config) CredentialProvider {
	return func(c *client) (auth.Authenticator, Decrypter, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		authenticator, err := c.Sessions().AWS(awsCfg...).Create()
		if err != nil {
			return nil, nil, err
		}
		return authenticator, decrypter, nil
	}
}

func RSA(credential *RSACredential) CredentialProvider {
	return func(c *client) (auth.Authenticator, Decrypter, error) {
		return auth.NewHTTPSigner(credential), credential, nil
	}
}
