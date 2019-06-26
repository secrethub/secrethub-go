package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/secrethub/secrethub-go/internals/api"
)

type KMSDecrypter struct {
	awsSession *session.Session
}

func NewKMSDecrypter(cfgs ...*aws.Config) (*KMSDecrypter, error) {
	sess, err := session.NewSession(cfgs...)
	if err != nil {
		return nil, handleError(err)
	}

	return &KMSDecrypter{
		awsSession: sess,
	}, nil
}

func (d KMSDecrypter) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	key, ok := ciphertext.Key.(*api.EncryptionKeyAWS)
	if !ok {
		return nil, api.ErrInvalidKeyType
	}
	keyARN, err := arn.Parse(api.StringValue(key.ID))
	if err != nil {
		return nil, api.ErrInvalidCiphertext
	}

	svc := kms.New(d.awsSession, aws.NewConfig().WithRegion(keyARN.Region))
	resp, err := svc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: ciphertext.Ciphertext,
	})
	if err != nil {
		return nil, handleError(err)
	}
	return resp.Plaintext, nil
}
