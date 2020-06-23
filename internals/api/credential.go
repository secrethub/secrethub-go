package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// Errors
var (
	ErrInvalidFingerprint                 = errAPI.Code("invalid_fingerprint").StatusError("fingerprint is invalid", http.StatusBadRequest)
	ErrTooShortFingerprint                = errAPI.Code("too_short_fingerprint").StatusErrorf("at least %d characters of the fingerprint must be entered", http.StatusBadRequest, ShortCredentialFingerprintMinimumLength)
	ErrCredentialFingerprintNotUnique     = errAPI.Code("fingerprint_not_unique").StatusErrorf("there are multiple credentials that start with the given fingerprint. Please use the full fingerprint", http.StatusConflict)
	ErrInvalidVerifier                    = errAPI.Code("invalid_verifier").StatusError("verifier is invalid", http.StatusBadRequest)
	ErrInvalidCredentialType              = errAPI.Code("invalid_credential_type").StatusError("credential type is invalid", http.StatusBadRequest)
	ErrInvalidCredentialDescription       = errAPI.Code("invalid_credential_description").StatusError("credential description can be at most 32 characters long", http.StatusBadRequest)
	ErrInvalidAWSEndpoint                 = errAPI.Code("invalid_aws_endpoint").StatusError("invalid AWS endpoint provided", http.StatusBadRequest)
	ErrInvalidProof                       = errAPI.Code("invalid_proof").StatusError("invalid proof provided for credential", http.StatusUnauthorized)
	ErrAWSAccountMismatch                 = errAPI.Code("aws_account_mismatch").StatusError("the AWS Account ID in the role ARN does not match the AWS Account ID of the AWS credentials used for authentication. Make sure you are using AWS credentials that correspond to the role you are trying to add.", http.StatusUnauthorized)
	ErrAWSAuthFailed                      = errAPI.Code("aws_auth_failed").StatusError("authentication not accepted by AWS", http.StatusUnauthorized)
	ErrAWSKMSKeyNotFound                  = errAPI.Code("aws_kms_key_not_found").StatusError("could not found the KMS key", http.StatusNotFound)
	ErrInvalidRoleARN                     = errAPI.Code("invalid_role_arn").StatusError("provided role is not a valid ARN", http.StatusBadRequest)
	ErrMissingMetadata                    = errAPI.Code("missing_metadata").StatusErrorPref("expecting %s metadata provided for credentials of type %s", http.StatusBadRequest)
	ErrInvalidMetadataValue               = errAPI.Code("invalid_metadata").StatusErrorPref("invalid value for metadata %s: %s", http.StatusBadRequest)
	ErrUnknownMetadataKey                 = errAPI.Code("unknown_metadata_key").StatusErrorPref("unknown metadata key: %s", http.StatusBadRequest)
	ErrRoleDoesNotMatch                   = errAPI.Code("role_does_not_match").StatusError("role in metadata does not match the verifier", http.StatusBadRequest)
	ErrGCPServiceAccountEmailDoesNotMatch = errAPI.Code("service_account_email_mismatch").StatusError("service account email in metadata does not match the verifier", http.StatusBadRequest)
	ErrCannotDisableCurrentCredential     = errAPI.Code("cannot_disable_current_credential").StatusError("cannot disable the credential that is currently used on this device", http.StatusConflict)
)

// Credential metadata keys
const (
	CredentialMetadataAWSKMSKey = "aws_kms_key_id"
	CredentialMetadataAWSRole   = "aws_role"

	CredentialMetadataGCPKMSKeyResourceID    = "gcp_kms_resource_id"
	CredentialMetadataGCPServiceAccountEmail = "gcp_service_account_email"
)

const (
	ShortCredentialFingerprintMinimumLength = 10
)

// Credential is used to authenticate to the API and to encrypt the account key.
type Credential struct {
	AccountID   uuid.UUID         `json:"account_id"`
	Type        CredentialType    `json:"type"`
	CreatedAt   time.Time         `json:"created_at"`
	Fingerprint string            `json:"fingerprint"`
	Description string            `json:"description"`
	Verifier    []byte            `json:"verifier"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Enabled     bool              `json:"enabled"`
}

// CredentialType is used to identify the type of algorithm that is used for a credential.
type CredentialType string

// Credential types
const (
	CredentialTypeKey               CredentialType = "key"
	CredentialTypeAWS               CredentialType = "aws"
	CredentialTypeBackupCode        CredentialType = "backup-code"
	CredentialTypeGCPServiceAccount CredentialType = "gcp-service-account"
)

const (
	// CredentialProofPrefixAWS is the prefix to use in AWS STS proof plaintext.
	CredentialProofPrefixAWS = "secrethub-allow-role="
)

var credentialTypesMetadata = map[CredentialType]map[string]func(string) error{
	CredentialTypeKey: {},
	CredentialTypeAWS: {
		CredentialMetadataAWSRole:   nil,
		CredentialMetadataAWSKMSKey: nil,
	},
	CredentialTypeGCPServiceAccount: {
		CredentialMetadataGCPServiceAccountEmail: ValidateGCPServiceAccountEmail,
		CredentialMetadataGCPKMSKeyResourceID:    ValidateGCPKMSKeyResourceID,
	},
	CredentialTypeBackupCode: {},
}

// CreateCredentialRequest contains the fields to add a credential to an account.
type CreateCredentialRequest struct {
	Type        CredentialType           `json:"type"`
	Fingerprint string                   `json:"fingerprint"`
	Description *string                  `json:"name,omitempty"`
	Verifier    []byte                   `json:"verifier"`
	Proof       interface{}              `json:"proof"`
	Metadata    map[string]string        `json:"metadata"`
	AccountKey  *CreateAccountKeyRequest `json:"account_key,omitempty"`
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
	case CredentialTypeGCPServiceAccount:
		dec.Proof = &CredentialProofGCPServiceAccount{}
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

	if req.Description != nil {
		if err := ValidateCredentialDescription(*req.Description); err != nil {
			return err
		}
	}

	expectedMetadata, validCredentialType := credentialTypesMetadata[req.Type]
	if !validCredentialType {
		return ErrInvalidCredentialType
	}
	for expectedMetadataKey, validator := range expectedMetadata {
		metadataValue, ok := req.Metadata[expectedMetadataKey]
		if !ok {
			return ErrMissingMetadata(expectedMetadataKey, req.Type)
		}
		if validator != nil {
			err := validator(metadataValue)
			if err != nil {
				return ErrInvalidMetadataValue(expectedMetadataKey, err)
			}
		}
	}
	for actualMetadataKey := range req.Metadata {
		if _, ok := expectedMetadata[actualMetadataKey]; !ok {
			return ErrUnknownMetadataKey(actualMetadataKey)
		}
	}

	if req.AccountKey != nil {
		if err := req.AccountKey.Validate(); err != nil {
			return err
		}
	}

	if validator, ok := req.Proof.(validator); ok {
		if err := validator.Validate(); err != nil {
			return err
		}
	}

	switch req.Type {
	case CredentialTypeAWS:
		role := req.Metadata[CredentialMetadataAWSRole]
		if !bytes.Equal(req.Verifier, []byte(role)) {
			return ErrRoleDoesNotMatch
		}
	case CredentialTypeGCPServiceAccount:
		serviceAccountEmail := req.Metadata[CredentialMetadataGCPServiceAccountEmail]
		if !bytes.Equal(req.Verifier, []byte(serviceAccountEmail)) {
			return ErrGCPServiceAccountEmailDoesNotMatch
		}
	case CredentialTypeBackupCode:
		decoded, err := base64.StdEncoding.DecodeString(string(req.Verifier))
		if err != nil {
			return ErrInvalidVerifier
		}
		if len(decoded) != sha256.Size {
			return ErrInvalidVerifier
		}
	}

	fingerprint := GetFingerprint(req.Type, req.Verifier)
	if req.Fingerprint != fingerprint {
		return ErrInvalidFingerprint
	}

	return nil
}

func (req *CreateCredentialRequest) RequiredLinkedID() (string, error) {
	switch req.Type {
	case CredentialTypeGCPServiceAccount:
		serviceAccountEmail, ok := req.Metadata[CredentialMetadataGCPServiceAccountEmail]
		if !ok {
			return "", errors.New("missing required metadata")
		}
		return ProjectIDFromGCPEmail(serviceAccountEmail)
	default:
		return "", errors.New("credential type does not require a linked ID")
	}
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

// CredentialProofKey is proof for when the credential type is GCPServiceAccount.
type CredentialProofGCPServiceAccount struct{}

// CredentialProofKey is proof for when the credential type is RSA.
type CredentialProofKey struct{}

// CredentialProofBackupCode is proof for when the credential type is backup key.
type CredentialProofBackupCode struct{}

// UpdateCredentialRequest contains the fields of a credential that can be updated.
type UpdateCredentialRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// Validate whether the UpdateCredentialRequest is a valid request.
func (req *UpdateCredentialRequest) Validate() error {
	return nil
}

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
