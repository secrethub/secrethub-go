package api

import (
	"net/http"

	"fmt"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors returned by the SecretHub API
var (
	errHub = errio.Namespace("server")

	// General
	ErrNotFound                  = errHub.Code("not_found").StatusError("Not found", http.StatusNotFound)
	ErrValidationFailed          = errHub.Code("validation_failed").StatusError("Validation errors", http.StatusExpectationFailed)
	ErrBadRequest                = errHub.Code("bad_request").StatusError("Bad request", http.StatusBadRequest)
	ErrTimeout                   = errHub.Code("timeout").StatusError("Timeout", http.StatusInternalServerError)
	ErrUnknownMethod             = errHub.Code("method_not_supported").StatusError("Method not supported", http.StatusNotImplemented)
	ErrDomainNotFound            = errHub.Code("domain_not_found").StatusError("Domain not found", http.StatusNotFound)
	ErrForbidden                 = errAPI.Code("forbidden").StatusError("You are not allowed to perform this action", http.StatusForbidden)
	ErrRequestNotAuthenticated   = errAPI.Code("not_authenticated").StatusError("Request was not authenticated", http.StatusUnauthorized)
	ErrNoAccountKeyForCredential = errAPI.Code("no_account_key_for_credential").StatusError("Could not find account-key for credential used for authentication.", http.StatusInternalServerError)
	ErrCannotPerformActionOnSelf = errAPI.Code("cannot_perform_action_on_self").StatusError("You cannot perform this action on yourself", http.StatusForbidden)
	ErrYourAccountNotKeyed       = errAPI.Code("account_not_keyed").StatusError("Your account has not been fully initialized", http.StatusBadRequest)

	// DB
	ErrDatabaseRecordAlreadyExists = errHub.Code("already_exists").StatusError("Already exists", http.StatusConflict)

	// Namespaces
	ErrNamespaceNotFound                      = errAPI.Code("namespace_not_found").StatusError("Namespace not found", http.StatusNotFound)
	ErrNamespaceAlreadyExists                 = errAPI.Code("namespace_already_exists").StatusError("this name already exists", http.StatusConflict)
	ErrCannotPerformActionOnPersonalNamespace = errAPI.Code("not_allowed_on_personal_namespace").StatusError("you cannot perform this action on a personal namespace", http.StatusForbidden)

	// Auth
	ErrAccountIncomplete    = errHub.Code("account_incomplete").StatusError("This account is not registered, please create a user first", http.StatusForbidden)
	ErrTokenNotVerified     = errHub.Code("token_not_verified").StatusError("Token not verified", http.StatusUnauthorized)
	ErrPasswordTooWeak      = errHub.Code("password_too_weak").StatusError("The password must be longer than 8 characters", http.StatusBadRequest)
	ErrSignatureNotVerified = errHub.Code("invalid_signature").StatusError("request was not signed by a valid credential", http.StatusUnauthorized)

	// Repos
	ErrRepoNotFound      = errHub.Code("repo_not_found").StatusError("Repo not found", http.StatusNotFound)
	ErrRepoAlreadyExists = errHub.Code("repo_already_exists").StatusError("Repo already exists, please create a different repo", http.StatusConflict)

	// Dirs
	ErrDirAlreadyExists    = errHub.Code("dir_already_exists").StatusError("Directory or secret already exists, create a different directory", http.StatusConflict)
	ErrDirNotFound         = errHub.Code("dir_not_found").StatusError("Directory not found", http.StatusNotFound)
	ErrParentDirNotFound   = errHub.Code("parent_dir_not_found").StatusError("Parent directory not found", http.StatusNotFound)
	ErrCannotRemoveRootDir = errHub.Code("cannot_remove_root_dir").StatusError("Root directory of a repository cannot be removed, remove the repository instead", http.StatusBadRequest)

	// Secrets
	ErrSecretAlreadyExists   = errHub.Code("secret_already_exists").StatusError("Secret or directory already exists, please update or create a different secret", http.StatusConflict)
	ErrSecretNotFound        = errHub.Code("secret_not_found").StatusError("Secret not found", http.StatusNotFound)
	ErrSecretVersionNotFound = errHub.Code("version_not_found").StatusError("Version of secret not found", http.StatusNotFound)
	ErrSecretKeyNotFound     = errHub.Code("secret_key_not_found").StatusError("Key for secret not found", http.StatusNotFound)

	// Secret Keys
	ErrSecretKeyFlagged = errAPI.Code("secret_key_flagged").StatusError(fmt.Sprintf("Cannot write new secrets with a key that has status %s", StatusFlagged), http.StatusBadRequest)
	ErrNoOKSecretKey    = errAPI.Code("no_secret_key_found_with_status_ok").StatusError(fmt.Sprintf("No secret key found with status %s", StatusOK), http.StatusNotFound)

	// Organization
	ErrOrgAlreadyExists         = errAPI.Code("org_already_exists").StatusError("Organization already exists, please create a different organization", http.StatusConflict)
	ErrOrgNotFound              = errAPI.Code("org_not_found").StatusError("Organization not found", http.StatusNotFound)
	ErrOrgMemberNotFound        = errAPI.Code("org_member_not_found").StatusError("Organization member not found", http.StatusNotFound)
	ErrOrgMemberAlreadyExists   = errAPI.Code("org_member_already_exists").StatusError("Organization member already exists", http.StatusConflict)
	ErrInvalidOrgRole           = errAPI.Code("invalid_org_role").StatusError("Organization role is invalid. Must be either `admin` or `member`", http.StatusBadRequest)
	ErrCannotRemoveLastOrgAdmin = errAPI.Code("cannot_remove_last_org_admin").StatusError("The last admin of an organization cannot be removed.", http.StatusForbidden)

	// User
	ErrUserEmailAlreadyExists = errHub.Code("user_email_already_exists").StatusError("That email address is already in use", http.StatusConflict)
	ErrUsernameAlreadyExists  = errHub.Code("username_already_exists").StatusError("A user with the given username already exists, please choose a different username", http.StatusConflict)
	ErrUserNotFound           = errHub.Code("user_not_found").StatusError("User not found, please verify username", http.StatusNotFound)
	ErrNotAUser               = errHub.Code("not_a_user").StatusError("Only users can perform this action", http.StatusForbidden)
	ErrNotOwner               = errHub.Code("not_owner").StatusError("Only repo owners can perform this action", http.StatusForbidden)
	ErrCannotAddYourself      = errHub.Code("cannot_add_self").StatusError("You cannot add yourself to your repo", http.StatusForbidden)
	ErrCannotRemoveYourself   = errHub.Code("cannot_remove_self").StatusError("You cannot remove yourself from your repo", http.StatusForbidden)

	// Service
	ErrServiceNotFound      = errHub.Code("service_not_found").StatusError("Service not found", http.StatusNotFound)
	ErrAccountIsNotService  = errHub.Code("not_a_service").StatusError("Account name does not represent a service", http.StatusBadRequest)
	ErrServiceAlreadyExists = errHub.Code("service_already_exists").StatusError("Service already exists, please create a different service", http.StatusConflict)
	ErrNoAdminAccess        = errHub.Code("no_admin_access").StatusError("Only accounts with Admin access can perform this action", http.StatusForbidden)
	ErrMemberAlreadyExists  = errHub.Code("member_already_exists").StatusError("The member already exists", http.StatusConflict)

	// Account
	ErrAccountNotFound    = errHub.Code("account_not_found").StatusError("Account not found", http.StatusNotFound)
	ErrUnknownSubjectType = errHub.Code("unknown_subject_type").Error("Unknown subject type") // no status error because it is an internal error
	ErrUnknownAccountType = errHub.Code("unknown_account_type").Error("Unknown account type") // no status error because it is an internal error
	ErrNotMemberOfRepo    = errHub.Code("not_repo_member").StatusError("Account is not a member of the repo", http.StatusBadRequest)

	// Credential
	ErrCredentialNotFound      = errHub.Code("credential_not_found").StatusError("Credential not found", http.StatusNotFound)
	ErrCredentialAlreadyExists = errHub.Code("credential_already_exists").StatusError("A credential with the given identifier already exists", http.StatusConflict)

	// Account key
	ErrPublicAccountKeyConflict = errHub.Code("public_account_key_does_not_match").StatusError("A different public account key is already registered for this account", http.StatusConflict)
	ErrPrivateKeyAlreadyExists  = errHub.Code("private_key_already_exists").StatusError("A private key for this credential already exists.", http.StatusConflict)
	ErrCredentialNotKeyed       = errHub.Code("credential_not_keyed").StatusError("The account key has not been encrypted for this credential", http.StatusNotFound)

	// Dirs
	ErrCannotRemoveLastRootAdmin = errHub.Code("cannot_remove_last_root_admin").StatusError("Cannot remove the last admin on the repo root", http.StatusBadRequest)
)
