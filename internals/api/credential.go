package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// Errors
var (
	ErrInvalidFingerprint    = errAPI.Code("invalid_fingerprint").StatusError("fingerprint is invalid", http.StatusBadRequest)
	ErrInvalidVerifier       = errAPI.Code("invalid_verifier").StatusError("verifier is invalid", http.StatusBadRequest)
	ErrInvalidCredentialType = errAPI.Code("invalid_credential_type").StatusError("credential type is invalid", http.StatusBadRequest)
	ErrInvalidAWSEndpoint    = errAPI.Code("invalid_aws_endpoint").StatusError("invalid AWS endpoint provided", http.StatusBadRequest)
	ErrInvalidProof          = errAPI.Code("invalid_proof").StatusError("invalid proof provided for credential", http.StatusUnauthorized)
	ErrAWSAccountMismatch    = errAPI.Code("aws_account_mismatch").StatusError("role account id does not match with authentication account id. Make sure you are using AWS credentials that correspond to the role you are trying to add.", http.StatusUnauthorized)
	ErrAWSAuthFailed         = errAPI.Code("aws_auth_failed").StatusError("authentication not accepted by AWS", http.StatusUnauthorized)
	ErrAWSKMSKeyNotFound     = errAPI.Code("aws_kms_key_not_found").StatusError("could not found the KMS key", http.StatusNotFound)
	ErrInvalidRoleARN        = errAPI.Code("invalid_role_arn").StatusError("provided role is not a valid ARN", http.StatusBadRequest)
)

// Credential is used to authenticate to the API and to encrypt the account key.
type Credential struct {
	AccountID   *uuid.UUID     `json:"account_id"`
	Type        CredentialType `json:"algorithm"`
	CreatedAt   time.Time      `json:"created_at"`
	Fingerprint string         `json:"fingerprint"`
	Name        string         `json:"name"`
	Verifier    []byte         `json:"verifier"`
}

// CredentialType is used to identify the type of algorithm that is used for a credential.
type CredentialType string

// Credential types
const (
	CredentialTypeRSA    CredentialType = "rsa"
	CredentialTypeAWSSTS CredentialType = "aws-sts"
)

const (
	// CredentialProofPrefixAWS is the prefix to use in AWS STS proof plaintext.
	CredentialProofPrefixAWS = "secrethub-allow-role="
)

// Validate validates whether the algorithm type is valid.
func (a CredentialType) Validate() error {
	if a == CredentialTypeRSA || a == CredentialTypeAWSSTS {
		return nil
	}
	return ErrInvalidCredentialType
}

// CreateCredentialRequest contains the fields to add a credential to an account.
type CreateCredentialRequest struct {
	Type        CredentialType `json:"type"`
	Fingerprint string         `json:"fingerprint"`
	Name        string         `json:"name,omitempty"`
	Verifier    []byte         `json:"verifier"`
	Proof       interface{}    `json:"proof"`
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
	case CredentialTypeAWSSTS:
		dec.Proof = &CredentialProofAWSSTS{}
	case CredentialTypeRSA:
		dec.Proof = &CredentialProofRSA{}
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
	if req.Type == CredentialTypeAWSSTS && req.Proof == nil {
		return ErrMissingField("proof")
	}
	fingerprint, err := CredentialFingerprint(req.Type, req.Verifier)
	if err != nil {
		return err
	}
	if req.Fingerprint != fingerprint {
		return ErrInvalidFingerprint
	}

	return nil
}

// CredentialProofAWSSTS is proof for when the credential type is AWSSTS.
type CredentialProofAWSSTS struct {
	Region  string `json:"region"`
	Request []byte `json:"request"`
}

// Validate whether the CredentialProofAWSSTS is valid.
func (p CredentialProofAWSSTS) Validate() error {
	if p.Region == "" {
		return ErrMissingField("region")
	}
	if p.Request == nil {
		return ErrMissingField("request")
	}
	return nil
}

// CredentialProofRSA is proof for when the credential type is RSA.
type CredentialProofRSA struct{}

// CredentialFingerprint returns the fingerprint of a credential.
func CredentialFingerprint(t CredentialType, verifier []byte) (string, error) {
	var toHash []byte
	if t == CredentialTypeRSA {
		// Provide compatibility with traditional RSA credentials.
		toHash = verifier
	} else {
		encodedVerifier := base64.RawStdEncoding.EncodeToString(verifier)
		toHash = []byte(fmt.Sprintf("credential_type=%s;verifier=%s", t, encodedVerifier))

	}
	h := sha256.New()
	_, err := h.Write(toHash)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
