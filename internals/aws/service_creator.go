package aws

import (
	"bytes"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"

	"github.com/secrethub/secrethub-go/internals/api"
)

// CredentialCreator is an implementation of the secrethub.Verifier and secrethub.Encrypter interface that can be used
// to create an AWS service account.
type CredentialCreator struct {
	stsSvc        stsiface.STSAPI
	kmsSvc        kmsiface.KMSAPI
	signingRegion string
	keyID         string
	role          string

	getEncryptRequest func(plaintext string, keyID string, kms kmsiface.KMSAPI) ([]byte, error)
}

// NewCredentialCreator returns a CredentialCreator that uses the provided AWS KMS key and IAM role to create a new credential.
// The AWS credential is configured with the optionally provided aws.Config.
func NewCredentialCreator(keyID, role string, cfgs ...*aws.Config) (*CredentialCreator, error) {
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
	return &CredentialCreator{
		stsSvc:            stsSvc,
		kmsSvc:            kmsSvc,
		signingRegion:     kmsSvc.SigningRegion,
		keyID:             keyID,
		role:              role,
		getEncryptRequest: GetEncryptRequest,
	}, nil
}

// Type returns the credential type of an AWS service.
func (c CredentialCreator) Type() api.CredentialType {
	return api.CredentialTypeAWSSTS
}

// Verifier returns the verifier of an AWS service.
func (c CredentialCreator) Verifier() ([]byte, error) {
	return []byte(c.role), nil
}

// AddProof adds proof of access to the AWS account to the CreateCredentialRequest.
func (c CredentialCreator) AddProof(req *api.CreateCredentialRequest) error {
	plaintext := api.CredentialProofPrefixAWS + c.role

	encryptReq, err := c.getEncryptRequest(plaintext, c.keyID, c.kmsSvc)
	if err != nil {
		return err
	}

	req.Proof = &api.CredentialProofAWSSTS{
		Region:  c.signingRegion,
		Request: encryptReq,
	}
	return nil
}

// Wrap the provided plaintext with using AWS KMS.
func (c CredentialCreator) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	resp, err := c.kmsSvc.Encrypt(&kms.EncryptInput{
		Plaintext: plaintext,
		KeyId:     aws.String(c.keyID),
	})
	if err != nil {
		return nil, handleError(err)
	}
	return api.NewEncryptedDataAWSKMS(resp.CiphertextBlob, api.NewEncryptionKeyAWS(aws.StringValue(resp.KeyId))), nil
}

// GetEncryptRequest returns the raw bytes of a signed AWS KMS EncryptRequest.
func GetEncryptRequest(plaintext string, keyID string, kmsSvc kmsiface.KMSAPI) ([]byte, error) {
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

// parseRole parses a given role and performs a best effort attempt
// to find and return the corresponding full ARN. The given role can
// be either a (partial) ARN or the role name and can be prefixed with
// "role/". Note that this is a best effort attempt so the returned value
// is not guaranteed to always be a valid ARN.
func parseRole(role string, stsSvc stsiface.STSAPI) (string, error) {
	if strings.Contains(role, ":") {
		return role, nil
	}

	identity, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", handleError(err)
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
