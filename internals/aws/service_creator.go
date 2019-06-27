package aws

import (
	"bytes"
	"strings"

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
	awsSession *session.Session
	keyID      string
	role       string
}

// NewServiceCreator returns a ServiceCreator that uses the provided AWS KMS key and IAM role to create a new service.
// The AWS service is configured with the optionally provided aws.Config.
func NewServiceCreator(keyID, role string, cfgs ...*aws.Config) (*ServiceCreator, error) {
	sess, err := session.NewSession(cfgs...)
	if err != nil {
		return nil, handleError(err)
	}

	getAccountId := func() (string, error) {
		stsSvc := sts.New(sess)
		identity, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		}
		return aws.StringValue(identity.Account), nil
	}

	role, err = parseRole(role, getAccountId)
	if err != nil {
		return nil, handleError(err)
	}

	return &ServiceCreator{
		awsSession: sess,
		keyID:      keyID,
		role:       role,
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

// Wrap the provided plaintext with using AWS KMS.
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

// parseRole tries to parse an inputted role into a role ARN.
// The input can either be an ARN or the name of a role (prefixed with role/ or not)
// The outputted value is not guaranteed to be a valid ARN.
func parseRole(role string, getAccountID func() (string, error)) (string, error) {
	if strings.Contains(role, ":") {
		return role, nil
	}

	accountID, err := getAccountID()
	if err != nil {
		return "", err
	}

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
