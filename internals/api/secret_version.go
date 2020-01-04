package api

import (
	"fmt"
	"strconv"
	"time"

	units "github.com/docker/go-units"
	"github.com/gofrs/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

const (
	// MaxEncryptedSecretSize is the maximum size of EncryptedSecretVersion.EncryptedData.
	MaxEncryptedSecretSize = (512*4/3 + 5) * units.KiB // 512 KiB corrected for base64 overhead (4/3) and metadata
)

// Status Constants
const (
	// StatusOK signals everything is in order.
	StatusOK = "ok"
	// StatusFlagged signals that a resource should be considered compromised and should be rotated/no longer used.
	StatusFlagged = "flagged"
	// StatusFailed signals that revocation cannot complete.
	StatusFailed = "failed"
)

// Errors
var (
	ErrEncryptedDataTooBig = errAPI.Code("encrypted_data_too_big").Error(fmt.Sprintf("maximum size of encrypted data is %s", units.BytesSize(MaxEncryptedSecretSize)))
)

// EncryptedSecretVersion represents a version of an encrypted Secret.
// It contains the encrypted data and the corresponding key.
type EncryptedSecretVersion struct {
	SecretVersionID uuid.UUID             `json:"secret_version_id"`
	Secret          *EncryptedSecret      `json:"secret"`
	Version         int                   `json:"version"`
	SecretKey       *EncryptedSecretKey   `json:"secret_key,omitempty"`
	EncryptedData   *crypto.CiphertextAES `json:"encrypted_data,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	Status          string                `json:"status"`
}

// Decrypt decrypts an EncryptedSecretVersion into a SecretVersion.
func (esv *EncryptedSecretVersion) Decrypt(accountKey *crypto.RSAPrivateKey) (*SecretVersion, error) {
	secret, err := esv.Secret.Decrypt(accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	var secretKey *SecretKey
	var data []byte
	if esv.SecretKey != nil && esv.EncryptedData != nil {
		secretKey, err = esv.SecretKey.Decrypt(accountKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		data, err = secretKey.Key.Decrypt(*esv.EncryptedData)
		if err != nil {
			return nil, err
		}
	}

	return &SecretVersion{
		SecretVersionID: esv.SecretVersionID,
		Secret:          secret,
		Version:         esv.Version,
		SecretKey:       secretKey,
		Data:            data,
		CreatedAt:       esv.CreatedAt,
		Status:          esv.Status,
	}, nil
}

// SecretVersion represents a version of a Secret without any encrypted data.
type SecretVersion struct {
	SecretVersionID uuid.UUID  `json:"secret_version_id"`
	Secret          *Secret    `json:"secret"`
	Version         int        `json:"version"`
	SecretKey       *SecretKey `json:"secret_key,omitempty"`
	Data            []byte     `json:"data,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Status          string     `json:"status"`
}

// IsLatest returns true when the secret version is the latest version of the secret.
func (sv *SecretVersion) IsLatest() bool {
	if sv.Secret == nil {
		return false
	}

	return sv.Secret.LatestVersion == sv.Version
}

// Name returns the secret name:version
func (sv *SecretVersion) Name() string {
	if sv.Secret == nil {
		return strconv.Itoa(sv.Version)
	}
	return fmt.Sprintf("%s:%d", sv.Secret.Name, sv.Version)
}

// ToAuditSubject converts an EncryptedSecret to an AuditSubject
func (es *EncryptedSecret) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID:       es.SecretID,
		Type:            AuditSubjectSecret,
		EncryptedSecret: es,
	}
}

// ToAuditSubject converts a SecretVersion to an AuditSubject
func (esv *EncryptedSecretVersion) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID:              esv.SecretVersionID,
		Type:                   AuditSubjectSecretVersion,
		EncryptedSecretVersion: esv,
	}
}

// CreateSecretVersionRequest contains the request fields for creating a
// secret version with a secret key.
type CreateSecretVersionRequest struct {
	EncryptedData crypto.CiphertextAES `json:"encrypted_data"`
	SecretKeyID   uuid.UUID            `json:"secret_key_id"`
}

// Validate validates the request fields.
func (csvr *CreateSecretVersionRequest) Validate() error {
	if csvr.SecretKeyID == uuid.Nil {
		return ErrInvalidSecretKeyID
	}

	encoded, err := csvr.EncryptedData.MarshalJSON()
	if err != nil {
		return err
	}

	if len(encoded) > MaxEncryptedSecretSize {
		return ErrEncryptedDataTooBig
	}

	return nil
}
