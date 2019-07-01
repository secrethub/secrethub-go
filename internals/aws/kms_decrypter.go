package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/secrethub/secrethub-go/internals/api"
)

// KMSDecrypter is an implementation of the secrethub.Decrypter interface that uses AWS KMS for decryption.
type KMSDecrypter struct {
	kmsSvcGetter func(region string) kmsiface.KMSAPI
}

// NewKMSDecrypter returns a new KMSDecrypter that uses the provided configuration to configure the AWS session.
func NewKMSDecrypter(cfgs ...*aws.Config) (*KMSDecrypter, error) {
	sess, err := session.NewSession(cfgs...)
	if err != nil {
		return nil, handleError(err)
	}

	return &KMSDecrypter{
		kmsSvcGetter: func(region string) kmsiface.KMSAPI {
			return kms.New(sess, aws.NewConfig().WithRegion(region))
		},
	}, nil
}

// Unwrap the provided ciphertext using AWS KMS.
func (d KMSDecrypter) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	key, ok := ciphertext.Key.(*api.EncryptionKeyAWS)
	if !ok {
		return nil, api.ErrInvalidKeyType
	}
	keyARN, err := arn.Parse(api.StringValue(key.ID))
	if err != nil {
		return nil, api.ErrInvalidCiphertext
	}

	svc := d.kmsSvcGetter(keyARN.Region)
	resp, err := svc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: ciphertext.Ciphertext,
	})
	if err != nil {
		return nil, handleError(err)
	}
	return resp.Plaintext, nil
}
