package api

import (
	"strings"
	"time"

	"bitbucket.org/zombiezen/cardcpx/natsort"
	"github.com/keylockerbv/secrethub-go/internals/api/uuid"
)

// Roles
const (
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// Org represents an organization account on SecretHub
type Org struct {
	OrgID       *uuid.UUID   `json:"org_id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	CreatedAt   time.Time    `json:"created_at"`
	Members     []*OrgMember `json:"members,omitempty"`
}

// SortOrgByName makes a list of orgs sortable.
type SortOrgByName []*Org

func (s SortOrgByName) Len() int {
	return len(s)
}
func (s SortOrgByName) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortOrgByName) Less(i, j int) bool {
	return natsort.Less(s[i].Name, s[j].Name)
}

// OrgMember represents a user's membership of an organization.
type OrgMember struct {
	OrgID         *uuid.UUID `json:"org_id"`
	AccountID     *uuid.UUID `json:"account_id"`
	Role          string     `json:"role"`
	CreatedAt     time.Time  `json:"created_at"`
	LastChangedAt time.Time  `json:"last_changed_at"`
	User          *User      `json:"user,omitempty"`
}

// SortOrgMemberByUsername makes a list of org members sortable.
type SortOrgMemberByUsername []*OrgMember

func (s SortOrgMemberByUsername) Len() int {
	return len(s)
}
func (s SortOrgMemberByUsername) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortOrgMemberByUsername) Less(i, j int) bool {
	if s[i].User == nil || s[j].User == nil {
		return false
	}
	return natsort.Less(s[i].User.Username, s[j].User.Username)
}

// CreateOrgRequest contains the required fields for creating an organization.
type CreateOrgRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Validate validates the request fields.
func (req CreateOrgRequest) Validate() error {
	err := ValidateOrgName(req.Name)
	if err != nil {
		return err
	}

	return ValidateOrgDescription(req.Description)
}

// CreateOrgMemberRequest contains the required fields for
// creating a user's organization membership.
type CreateOrgMemberRequest struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Validate validates the request fields.
func (req CreateOrgMemberRequest) Validate() error {
	err := ValidateUsername(req.Username)
	if err != nil {
		return err
	}

	return ValidateOrgRole(req.Role)
}

// UpdateOrgMemberRequest contains the required fields for
// updating a user's organization membership.
type UpdateOrgMemberRequest struct {
	Role string `json:"role"`
}

// Validate validates the request fields.
func (req UpdateOrgMemberRequest) Validate() error {
	return ValidateOrgRole(req.Role)
}

// ValidateOrgRole validates an organization role.
func ValidateOrgRole(role string) error {
	switch strings.ToLower(role) {
	case OrgRoleAdmin, OrgRoleMember:
		return nil
	default:
		return ErrInvalidOrgRole
	}
}
