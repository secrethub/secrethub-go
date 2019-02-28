package api

import (
	"fmt"
	"net/http"
	"time"

	"bitbucket.org/zombiezen/cardcpx/natsort"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// Errors
var (
	ErrInvalidRepoName = errAPI.Code("invalid_repo_name").StatusError(
		"repo names must be between 1 and 32 characters long and "+
			"may only contain letters, numbers, dashes (-), underscores (_), and dots (.)",
		http.StatusBadRequest,
	)
	ErrInvalidRepoEncryptionKey        = errAPI.Code("invalid_repo_encryption_key").StatusError("repo encryption key is invalid", http.StatusBadRequest)
	ErrInvalidRepoIndexKey             = errAPI.Code("invalid_repo_index_key").StatusError("repo index key is invalid", http.StatusBadRequest)
	ErrInvalidAccountID                = errAPI.Code("invalid_account_id").StatusError("account id is invalid", http.StatusBadRequest)
	ErrInvalidSecretMemberAccountID    = errAPI.Code("invalid_secret_member_account_id").StatusError("account id of secret member does not correspond to the account id of the invited user", http.StatusBadRequest)
	ErrInvalidSecretKeyMemberAccountID = errAPI.Code("invalid_secret_key_member_account_id").StatusError("account id of secret key member does not correspond to the account id of the invited user", http.StatusBadRequest)
	ErrRepoMemberNotFound              = errAPI.Code("repo_member_not_found").StatusError("repo member not found", http.StatusNotFound)
	ErrNoRootDir                       = errAPI.Code("no_root_dir").StatusError("there is no create dir request for the root directory", http.StatusBadRequest)
	ErrNoRepoMember                    = errAPI.Code("no_repo_member").StatusError("there is no create repo member request for the root directory", http.StatusBadRequest)
)

// Repo represents a repo on SecretHub.
type Repo struct {
	RepoID         *uuid.UUID `json:"repo_id"`
	Owner          string     `json:"owner"`
	Name           string     `json:"name"`
	CreatedAt      *time.Time `json:"created_at"`
	LastModifiedAt *time.Time `json:"last_modified_at"`
	Status         string     `json:"status"`
	SecretCount    int        `json:"secret_count,omitempty"`
	MemberCount    int        `json:"member_count,omitempty"`
}

// Path returns the full repository path.
func (r Repo) Path() RepoPath {
	return RepoPath(fmt.Sprintf("%s/%s", r.Owner, r.Name))
}

// Trim removes all non-essential fields from Repo for output
func (r Repo) Trim() *Repo {
	return &Repo{
		RepoID:         r.RepoID,
		Name:           r.Name,
		Owner:          r.Owner,
		CreatedAt:      r.CreatedAt,
		LastModifiedAt: r.LastModifiedAt,
	}
}

// ToAuditSubject converts a Repo to an AuditSubject
func (r Repo) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID: r.RepoID,
		Type:      AuditSubjectRepo,
		Repo:      r.Trim(),
	}
}

// SortRepoByName makes a list of repos sortable.
type SortRepoByName []*Repo

func (r SortRepoByName) Len() int {
	return len(r)
}
func (r SortRepoByName) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}
func (r SortRepoByName) Less(i, j int) bool {
	if r[i].Owner != r[j].Owner {
		return natsort.Less(r[i].Owner, r[j].Owner)
	}

	return natsort.Less(r[i].Name, r[j].Name)
}

// CreateRepoRequest contains the required fields for a Repo.
type CreateRepoRequest struct {
	Name       string                   `json:"name"`
	RootDir    *CreateDirRequest        `json:"root_dir"`
	RepoMember *CreateRepoMemberRequest `json:"repo_member"`
}

// Validate validates the request fields.
func (crr CreateRepoRequest) Validate() error {
	err := ValidateRepoName(crr.Name)
	if err != nil {
		return err
	}

	if crr.RootDir == nil {
		return ErrNoRootDir
	}

	err = crr.RootDir.Validate()
	if err != nil {
		return err
	}

	if crr.RepoMember == nil {
		return ErrNoRepoMember
	}

	return crr.RepoMember.Validate()
}

// RepoMember represents a member of a SecretHub repo.
type RepoMember struct {
	RepoID    *uuid.UUID `json:"repo_id"`
	AccountID *uuid.UUID `json:"account_id"`
	CreatedAt time.Time  `json:"created_at"`
}

// CreateRepoMemberRequest contains the required fields for adding a user to a repo.
type CreateRepoMemberRequest struct {
	RepoEncryptionKey []byte `json:"repo_encryption_key"`
	RepoIndexKey      []byte `json:"repo_index_key"`
}

// Validate validates a CreateRepoMemberRequests
func (req CreateRepoMemberRequest) Validate() error {
	if req.RepoIndexKey == nil {
		return ErrInvalidRepoEncryptionKey
	}

	if req.RepoEncryptionKey == nil {
		return ErrInvalidRepoIndexKey
	}

	return nil
}

// InviteUserRequest contains the required fields for inviting a user to a repo.
type InviteUserRequest struct {
	AccountID  *uuid.UUID               `json:"account_id"`
	RepoMember *CreateRepoMemberRequest `json:"repo_member"`
}

// Validate validates a InviteUserRequest
func (req InviteUserRequest) Validate() error {
	if req.AccountID == nil {
		return ErrInvalidAccountID
	}

	return req.RepoMember.Validate()
}

// RepoKeys contains the response with the repo key.
type RepoKeys struct {
	RepoEncryptionKey []byte `json:"repo_encryption_key"`
	RepoIndexKey      []byte `json:"repo_index_key"`
}
