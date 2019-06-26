package aws

import (
	"bytes"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/secrethub/secrethub-go/internals/api"
)

type ServiceCreator struct {
	awsSession *session.Session
	keyID      string
	role       string
}

func NewServiceCreator(keyID, role string, cfgs ...*aws.Config) (*ServiceCreator, error) {
	sess, err := session.NewSession(cfgs...)
	if err != nil {
		return nil, handleError(err)
	}

	return &ServiceCreator{
		awsSession: sess,
		keyID:      keyID,
		role:       role,
	}, nil
}

func (c ServiceCreator) Type() api.CredentialType {
	return api.CredentialTypeAWSSTS
}

func (c ServiceCreator) Verifier() ([]byte, error) {
	return []byte(c.role), nil
}

func (c ServiceCreator) AddProof(req *api.CreateCredentialRequest) error {
	svc := kms.New(c.awsSession)

	plaintext := api.CredentialAWSSTSPlaintextPrefix + c.role
	encryptReq, _ := svc.EncryptRequest(&kms.EncryptInput{
		KeyId:     aws.String(c.keyID),
		Plaintext: []byte(plaintext),
	})

	err := encryptReq.Sign()
	if err != nil {
		return handleError(err)
	}

	var buf bytes.Buffer
	err = encryptReq.HTTPRequest.Write(&buf)
	if err != nil {
		return handleError(err)
	}
	req.Proof = &api.CredentialProofAWSSTS{
		Region:  api.String(svc.SigningRegion),
		Request: buf.Bytes(),
	}
	return nil
}

func (c ServiceCreator) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	svc := kms.New(c.awsSession)

	resp, err := svc.Encrypt(&kms.EncryptInput{
		Plaintext: plaintext,
		KeyId:     aws.String(c.keyID),
	})
	if err != nil {
		return nil, handleError(err)
	}
	return api.NewEncryptedDataAWSKMS(resp.CiphertextBlob, api.NewEncryptionKeyAWS(aws.StringValue(resp.KeyId))), nil
}
