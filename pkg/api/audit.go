package api

import (
	"time"

	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
)

// AuditAction values.
const (
	AuditActionUnknown AuditAction = "unknown"
	AuditActionCreate  AuditAction = "create"
	AuditActionRead    AuditAction = "read"
	AuditActionUpdate  AuditAction = "update"
	AuditActionDelete  AuditAction = "delete"
)

// Audit represents an AuditEvent in SecretHub.
type Audit struct {
	EventID   *uuid.UUID   `json:"event_id"`
	Action    AuditAction  `json:"action"`
	IPAddress string       `json:"ip_address"`
	LoggedAt  time.Time    `json:"logged_at"`
	Repo      Repo         `json:"repo"`
	Actor     AuditActor   `json:"actor"`
	Subject   AuditSubject `json:"subject"`
}

// AuditAction represents the action that was performed to create this audit event.
type AuditAction string

// AuditActor represents the Account of an AuditEvent
type AuditActor struct {
	ActorID *uuid.UUID `json:"id,omitempty"`
	Deleted bool       `json:"deleted,omitempty"`
	// Type is `user` or `service`. When actor is deleted, type is always `account`
	Type    string   `json:"type"`
	User    *User    `json:"user,omitempty"`
	Service *Service `json:"service,omitempty"`
}

// AuditSubjectType represents the type of an audit subject.
type AuditSubjectType string

// AuditSubjectTypeList represents a list of AuditSubjectTypes.
type AuditSubjectTypeList []AuditSubjectType

// The different options for an AuditSubjectType.
const (
	AuditSubjectAccount       = "account"
	AuditSubjectUser          = "user"
	AuditSubjectService       = "service"
	AuditSubjectSecret        = "secret"
	AuditSubjectSecretVersion = "secret_version"
	AuditSubjectSecretKey     = "secret_key"
	AuditSubjectSecretMember  = "permission"
	AuditSubjectRepo          = "repo"
	AuditSubjectRepoMember    = "repo_member"
	AuditSubjectRepoKey       = "repo_key"
)

// AuditSubject represents the Subject of an AuditEvent
type AuditSubject struct {
	SubjectID *uuid.UUID `json:"id,omitempty"`
	Deleted   bool       `json:"deleted,omitempty"`
	// Type is `user`, `service`, `repo`, `secret`, `secret_version` or `secret_key`. When subject is deleted, user and service are indicated with type `account`
	Type                   AuditSubjectType        `json:"type"`
	User                   *User                   `json:"user,omitempty"`
	Service                *Service                `json:"service,omitempty"`
	Repo                   *Repo                   `json:"repo,omitempty"`
	EncryptedSecret        *EncryptedSecret        `json:"encrypted_secret,omitempty"` // This is converted to a Secret by the Client.
	Secret                 *Secret                 `json:"secret,omitempty"`
	EncryptedSecretVersion *EncryptedSecretVersion `json:"encrypted_secret_version,omitempty"` // This is converted to a SecretVersion by the Client.
	SecretVersion          *SecretVersion          `json:"secret_version,omitempty"`
}

// Join converts an AuditSubjectTypeList to a string where each AuditSubjectType is separated by separator.
func (l AuditSubjectTypeList) Join(separator string) string {
	output := ""
	for i, t := range l {
		output += string(t)
		if i < len(l)-1 {
			output += separator
		}
	}
	return output
}
