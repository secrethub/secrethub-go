package aws

import (
	"bytes"
	"strings"

	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"

	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/secrethub/secrethub-go/internals/api"
)

// ServiceCreator is an implementation of the secrethub.Verifier and secrethub.Encrypter interface that can be used
// to create an AWS service account.
type ServiceCreator struct {
	stsSvc        stsiface.STSAPI
	kmsSvc        kmsiface.KMSAPI
	signingRegion string
	keyID         string
	role          string

	getEncryptRequest func(plaintext string, keyID string, kms kmsiface.KMSAPI) ([]byte, error)
}

// NewServiceCreator returns a ServiceCreator that uses the provided AWS KMS key and IAM role to create a new service.
// The AWS service is configured with the optionally provided aws.Config.
func NewServiceCreator(keyID, role string, cfgs ...*aws.Config) (*ServiceCreator, error) {
	sess, err := session.NewSession(cfgs...)
	if err != nil {
		return nil, handleError(err)
	}

	stsSvc := sts.New(sess)

	role, err = parseRole(role, stsSvc)
	if err != nil {
		return nil, handleError(err)
	}

	kmsSvc := kms.New(sess)
	return &ServiceCreator{
		stsSvc:            stsSvc,
		kmsSvc:            kmsSvc,
		signingRegion:     kmsSvc.SigningRegion,
		keyID:             keyID,
		role:              role,
		getEncryptRequest: getEncryptRequest,
	}, nil
}

// Type returns the credential type of an AWS service.
func (c ServiceCreator) Type() api.CredentialType {
	return api.CredentialTypeAWSSTS
}

// Verifier returns the verifier of an AWS service.
func (c ServiceCreator) Verifier() ([]byte, error) {
	return []byte(c.role), nil
}

// AddProof adds proof of access to the AWS account to the CreateCredentialRequest.
func (c ServiceCreator) AddProof(req *api.CreateCredentialRequest) error {
	plaintext := api.CredentialAWSSTSPlaintextPrefix + c.role

	encryptReq, err := c.getEncryptRequest(plaintext, c.keyID, c.kmsSvc)
	if err != nil {
		return err
	}

	req.Proof = &api.CredentialProofAWSSTS{
		Region:  api.String(c.signingRegion),
		Request: encryptReq,
	}
	return nil
}

// Wrap the provided plaintext with using AWS KMS.
func (c ServiceCreator) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	resp, err := c.kmsSvc.Encrypt(&kms.EncryptInput{
		Plaintext: plaintext,
		KeyId:     aws.String(c.keyID),
	})
	if err != nil {
		return nil, handleError(err)
	}
	return api.NewEncryptedDataAWSKMS(resp.CiphertextBlob, api.NewEncryptionKeyAWS(aws.StringValue(resp.KeyId))), nil
}

func getEncryptRequest(plaintext string, keyID string, kmsSvc kmsiface.KMSAPI) ([]byte, error) {
	encryptReq, _ := kmsSvc.EncryptRequest(&kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: []byte(plaintext),
	})

	err := encryptReq.Sign()
	if err != nil {
		return nil, handleError(err)
	}

	var buf bytes.Buffer
	err = encryptReq.HTTPRequest.Write(&buf)
	if err != nil {
		return nil, handleError(err)
	}
	return buf.Bytes(), nil
}

// parseRole tries to parse an inputted role into a role ARN.
// The input can either be an ARN or the name of a role (prefixed with role/ or not)
// The outputted value is not guaranteed to be a valid ARN.
func parseRole(role string, stsSvc stsiface.STSAPI) (string, error) {
	if strings.Contains(role, ":") {
		return role, nil
	}

	identity, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	accountID := aws.StringValue(identity.Account)

	if !strings.HasPrefix(role, "role/") {
		role = "role/" + role
	}
	return arn.ARN{
		Partition: endpoints.AwsPartitionID,
		Service:   iam.ServiceName,
		AccountID: accountID,
		Resource:  role,
	}.String(), nil
}
