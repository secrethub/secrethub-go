package api

import (
	"net/http"
	"time"

	"bitbucket.org/zombiezen/cardcpx/natsort"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// Errors
var (
	ErrInvalidDirName = errAPI.Code("invalid_dir_name").StatusError(
		"directory names must be between 2 and 32 characters long and "+
			"may only contain letters, numbers, dashes (-), underscores (_), and dots (.)",
		http.StatusBadRequest,
	)
	ErrInvalidDirBlindName    = errAPI.Code("invalid_dir_blind_name").StatusErrorf("directory blind name is invalid: %s", http.StatusBadRequest, ErrInvalidBlindName)
	ErrInvalidParentBlindName = errAPI.Code("invalid_parent_blind_name").StatusErrorf("directory parent blind name is invalid: %s", http.StatusBadRequest, ErrInvalidBlindName)
)

// EncryptedDir represents an encrypted Dir.
// The names are encrypted and so are the names of SubDirs and Secrets.
// The secrets contain no encrypted data, only the encrypted name.
type EncryptedDir struct {
	DirID          *uuid.UUID               `json:"dir_id"`
	BlindName      string                   `json:"blind_name"`
	EncryptedName  crypto.EncodedCiphertext `json:"encrypted_name"`
	ParentID       *uuid.UUID               `json:"parent_id"`
	Status         string                   `json:"status"`
	CreatedAt      time.Time                `json:"created_at"`
	LastModifiedAt time.Time                `json:"last_modified_at"`
}

// Decrypt decrypts an EncryptedDir into a Dir.
func (ed *EncryptedDir) Decrypt(accountKey *crypto.RSAKey) (*Dir, error) {
	decodedName, err := ed.EncryptedName.Decode()
	if err != nil {
		return nil, errio.Error(err)
	}

	decryptedName, err := decodedName.Decrypt(accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	result := &Dir{
		DirID:          ed.DirID,
		BlindName:      ed.BlindName,
		Name:           string(decryptedName),
		ParentID:       ed.ParentID,
		Status:         ed.Status,
		CreatedAt:      ed.CreatedAt,
		LastModifiedAt: ed.LastModifiedAt,
	}

	return result, nil
}

// Dir represents an directory.
// A dir belongs to a repo and contains other dirs and secrets.
type Dir struct {
	DirID          *uuid.UUID `json:"dir_id"`
	BlindName      string     `json:"blind_name"`
	Name           string     `json:"name"`
	ParentID       *uuid.UUID `json:"parent_id"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	LastModifiedAt time.Time  `json:"last_modified_at"`
	SubDirs        []*Dir     `json:"sub_dirs"`
	Secrets        []*Secret  `json:"secrets"`
}

// CreateDirRequest contains the request fields for creating a new directory.
type CreateDirRequest struct {
	BlindName       string `json:"blind_name"`
	ParentBlindName string `json:"parent_blind_name"`

	EncryptedNames []EncryptedNameRequest `json:"encrypted_names"`
}

// Validate validates the CreateDirRequest to be valid.
func (cdr *CreateDirRequest) Validate() error {
	err := ValidateBlindName(cdr.BlindName)
	if err != nil {
		return ErrInvalidDirBlindName
	}

	err = ValidateBlindName(cdr.ParentBlindName)
	if err != nil {
		return ErrInvalidParentBlindName
	}

	if len(cdr.EncryptedNames) < 1 {
		return ErrNotEncryptedForAccounts
	}

	unique := make(map[uuid.UUID]int)
	for _, encryptedName := range cdr.EncryptedNames {
		err := encryptedName.Validate()
		if err != nil {
			return err
		}

		unique[*encryptedName.AccountID]++
	}

	for _, count := range unique {
		if count != 1 {
			return ErrNotUniquelyEncryptedForAccounts
		}
	}

	return nil
}

// SortDirByName makes a list of Dir sortable.
type SortDirByName []*Dir

func (d SortDirByName) Len() int {
	return len(d)
}
func (d SortDirByName) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d SortDirByName) Less(i, j int) bool {
	return natsort.Less(d[i].Name, d[j].Name)
}
