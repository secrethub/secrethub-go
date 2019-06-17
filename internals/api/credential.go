package api

import (
	"encoding/json"
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
	ErrInvalidProof          = errAPI.Code("invalid_proof").StatusError("invalid proof provided for credential", http.StatusBadRequest)
	ErrAWSAuthFailed         = errAPI.Code("aws_auth_failed").StatusError("authentication not accepted by AWS", http.StatusForbidden)
	ErrAWSException          = errAPI.Code("aws_exception").StatusError("unknown error occurred while contacting AWS", http.StatusFailedDependency)
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
	CredentialTypeAWSSTS                = "aws-sts"
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
	Type        *CredentialType `json:"type"`
	Fingerprint *string         `json:"fingerprint"`
	Name        *string         `json:"name,omitempty"`
	Verifier    []byte          `json:"verifier"`
	Proof       interface{}     `json:"proof"`
}

func (req *CreateCredentialRequest) UnmarshalJSON(b []byte) error {
	encodedProof := json.RawMessage{}
	req.Proof = &encodedProof
	err := json.Unmarshal(b, &req)
	if err != nil {
		return err
	}
	if req.Type == nil {
		return ErrMissingField("type")
	}

	switch *req.Type {
	case CredentialTypeAWSSTS:
		req.Proof = &CredentialProofAWSSTS{}
	case CredentialTypeRSA:
		req.Proof = &CredentialProofRSA{}
	default:
		return ErrInvalidCredentialType
	}

	err = json.Unmarshal(encodedProof, req.Proof)
	if err != nil {
		return err
	}
	return nil
}

// Validate validates the request fields.
func (req *CreateCredentialRequest) Validate() error {
	if req.Fingerprint == nil {
		return ErrMissingField("fingerprint")
	}
	if req.Verifier == nil {
		return ErrMissingField("verifier")
	}
	if req.Type == nil {
		return ErrMissingField("type")
	}
	err := req.Type.Validate()
	if err != nil {
		return err
	}
	if *req.Type == CredentialTypeAWSSTS && req.Proof == nil {
		return ErrMissingField("proof")
	}

	return nil
}

// CredentialProofAWSSTS is proof for when the credential type is AWSSTS.
type CredentialProofAWSSTS struct {
	Region  *string `json:"region"`
	Request []byte  `json:"request"`
}

func (p CredentialProofAWSSTS) Validate() error {
	if p.Region == nil {
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
func CredentialFingerprint(t CredentialType, verifier []byte) string {
	var toHash []byte
	if t == CredentialTypeRSA {
		// Provide compatibility with traditional RSA credentials.
		toHash = verifier
	} else {
		encodedVerifier := base64.RawStdEncoding.EncodeToString(verifier)
		toHash = []byte(fmt.Sprintf("credential_type=%s;verifier=%s", t, encodedVerifier))

	}
	h := sha256.New()
	h.Write(toHash)
	return hex.EncodeToString(h.Sum(nil))
}
