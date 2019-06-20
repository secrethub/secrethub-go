package aws

import (
	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/secrethub/secrethub-go/internals/api"
)

type KMSDecrypter struct {
	awsSession *session.Session
}

func NewKMSDecrypter(cfgs ...*aws.Config) (*KMSDecrypter, error) {
	sess, err := session.NewSession(aws.NewConfig().WithRegion("eu-west-1"))
	if err != nil {
		return nil, err
	}

	return &KMSDecrypter{
		awsSession: sess,
	}, nil
}

func (d KMSDecrypter) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	svc := kms.New(d.awsSession)

	resp, err := svc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: ciphertext.Ciphertext,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
