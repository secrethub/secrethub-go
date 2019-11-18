package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// Errors
var (
	ErrInvalidFingerprint    = errAPI.Code("invalid_fingerprint").StatusError("fingerprint is invalid", http.StatusBadRequest)
	ErrInvalidVerifier       = errAPI.Code("invalid_verifier").StatusError("verifier is invalid", http.StatusBadRequest)
	ErrInvalidCredentialType = errAPI.Code("invalid_credential_type").StatusError("credential type is invalid", http.StatusBadRequest)
	ErrInvalidAWSEndpoint    = errAPI.Code("invalid_aws_endpoint").StatusError("invalid AWS endpoint provided", http.StatusBadRequest)
	ErrInvalidProof          = errAPI.Code("invalid_proof").StatusError("invalid proof provided for credential", http.StatusUnauthorized)
	ErrAWSAccountMismatch    = errAPI.Code("aws_account_mismatch").StatusError("the AWS Account ID in the role ARN does not match the AWS Account ID of the AWS credentials used for authentication. Make sure you are using AWS credentials that correspond to the role you are trying to add.", http.StatusUnauthorized)
	ErrAWSAuthFailed         = errAPI.Code("aws_auth_failed").StatusError("authentication not accepted by AWS", http.StatusUnauthorized)
	ErrAWSKMSKeyNotFound     = errAPI.Code("aws_kms_key_not_found").StatusError("could not found the KMS key", http.StatusNotFound)
	ErrInvalidRoleARN        = errAPI.Code("invalid_role_arn").StatusError("provided role is not a valid ARN", http.StatusBadRequest)
	ErrMissingMetadata       = errAPI.Code("missing_metadata").StatusErrorPref("expecting %s metadata provided for credentials of type %s", http.StatusBadRequest)
	ErrInvalidMetadataKey    = errAPI.Code("invalid_metadata_key").StatusErrorPref("invalid metadata key %s for credential type %s", http.StatusBadRequest)
	ErrUnknownMetadataKey    = errAPI.Code("unknown_metadata_key").StatusErrorPref("unknown metadata key: %s", http.StatusBadRequest)
	ErrRoleDoesNotMatch      = errAPI.Code("role_does_not_match").StatusError("role in metadata does not match the verifier", http.StatusBadRequest)
)

// Credential metadata keys
const (
	CredentialMetadataAWSKMSKey = "aws_kms_key_id"
	CredentialMetadataAWSRole   = "aws_role"
)

// Credential is used to authenticate to the API and to encrypt the account key.
type Credential struct {
	AccountID   uuid.UUID         `json:"account_id"`
	Type        CredentialType    `json:"type"`
	CreatedAt   time.Time         `json:"created_at"`
	Fingerprint string            `json:"fingerprint"`
	Name        string            `json:"name"`
	Verifier    []byte            `json:"verifier"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CredentialType is used to identify the type of algorithm that is used for a credential.
type CredentialType string

// Credential types
const (
	CredentialTypeKey        CredentialType = "key"
	CredentialTypeAWS        CredentialType = "aws"
	CredentialTypeBackupCode CredentialType = "backup-code"
)

const (
	// CredentialProofPrefixAWS is the prefix to use in AWS STS proof plaintext.
	CredentialProofPrefixAWS = "secrethub-allow-role="
)

// Validate validates whether the algorithm type is valid.
func (a CredentialType) Validate() error {
	var credentialTypeList = map[CredentialType]struct{}{
		CredentialTypeKey:        {},
		CredentialTypeAWS:        {},
		CredentialTypeBackupCode: {},
	}
	if _, ok := credentialTypeList[a]; !ok {
		return ErrInvalidCredentialType
	}
	return nil
}

// CreateCredentialRequest contains the fields to add a credential to an account.
type CreateCredentialRequest struct {
	Type        CredentialType    `json:"type"`
	Fingerprint string            `json:"fingerprint"`
	Name        string            `json:"name,omitempty"`
	Verifier    []byte            `json:"verifier"`
	Proof       interface{}       `json:"proof"`
	Metadata    map[string]string `json:"metadata"`
}

// UnmarshalJSON converts a JSON representation into a CreateCredentialRequest with the correct Proof.
func (req *CreateCredentialRequest) UnmarshalJSON(b []byte) error {
	// Declare a private type to avoid recursion into this function.
	type createCredentialRequest CreateCredentialRequest

	var rawMessage json.RawMessage
	dec := createCredentialRequest{
		Proof: &rawMessage,
	}

	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}
	if dec.Type == "" {
		return ErrMissingField("type")
	}

	switch dec.Type {
	case CredentialTypeAWS:
		dec.Proof = &CredentialProofAWS{}
	case CredentialTypeKey:
		dec.Proof = &CredentialProofKey{}
	case CredentialTypeBackupCode:
		dec.Proof = &CredentialProofBackupCode{}
	default:
		return ErrInvalidCredentialType
	}
	if rawMessage != nil {
		err = json.Unmarshal(rawMessage, dec.Proof)
		if err != nil {
			return err
		}
	}
	*req = CreateCredentialRequest(dec)
	return nil
}

// Validate validates the request fields.
func (req *CreateCredentialRequest) Validate() error {
	if req.Fingerprint == "" {
		return ErrMissingField("fingerprint")
	}

	if req.Verifier == nil {
		return ErrMissingField("verifier")
	}

	if req.Type == "" {
		return ErrMissingField("type")
	}

	err := req.Type.Validate()
	if err != nil {
		return err
	}

	if req.Type == CredentialTypeBackupCode {
		decoded, err := base64.StdEncoding.DecodeString(string(req.Verifier))
		if err != nil {
			return ErrInvalidVerifier
		}
		if len(decoded) != sha256.Size {
			return ErrInvalidVerifier
		}
	}

	if req.Type == CredentialTypeAWS && req.Proof == nil {
		return ErrMissingField("proof")
	}

	fingerprint := GetFingerprint(req.Type, req.Verifier)
	if req.Fingerprint != fingerprint {
		return ErrInvalidFingerprint
	}

	if req.Type == CredentialTypeAWS {
		role, ok := req.Metadata[CredentialMetadataAWSRole]
		if !ok {
			return ErrMissingMetadata(CredentialMetadataAWSRole, CredentialTypeAWS)
		}
		if !bytes.Equal(req.Verifier, []byte(role)) {
			return ErrRoleDoesNotMatch
		}

		_, ok = req.Metadata[CredentialMetadataAWSKMSKey]
		if !ok {
			return ErrMissingMetadata(CredentialMetadataAWSKMSKey, CredentialTypeAWS)
		}
	}

	for key := range req.Metadata {
		if key != CredentialMetadataAWSKMSKey && key != CredentialMetadataAWSRole {
			return ErrUnknownMetadataKey(key)
		} else if req.Type != CredentialTypeAWS {
			return ErrInvalidMetadataKey(key, req.Type)
		}
	}

	return nil
}

// CredentialProofAWS is proof for when the credential type is AWSSTS.
type CredentialProofAWS struct {
	Region  string `json:"region"`
	Request []byte `json:"request"`
}

// Validate whether the CredentialProofAWS is valid.
func (p CredentialProofAWS) Validate() error {
	if p.Region == "" {
		return ErrMissingField("region")
	}
	if p.Request == nil {
		return ErrMissingField("request")
	}
	return nil
}

// CredentialProofKey is proof for when the credential type is RSA.
type CredentialProofKey struct{}

// CredentialProofBackupCode is proof for when the credential type is backup key.
type CredentialProofBackupCode struct{}

// GetFingerprint returns the fingerprint of a credential.
func GetFingerprint(t CredentialType, verifier []byte) string {
	var toHash []byte
	if t == CredentialTypeKey {
		// Provide compatibility with traditional RSA credentials.
		toHash = verifier
	} else {
		encodedVerifier := base64.RawStdEncoding.EncodeToString(verifier)
		toHash = []byte(fmt.Sprintf("credential_type=%s;verifier=%s", t, encodedVerifier))

	}
	return hex.EncodeToString(crypto.SHA256(toHash))
}
