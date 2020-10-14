package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
)

const (
	serviceDescriptionMaxLength = 2048
	uniformNameMinimumLength    = 3
	uniformNameMaximumLength    = 32

	patternUniformNameCharacters = `[_\-\.a-zA-Z0-9]`
	patternAlphanumeric          = `[a-zA-Z0-9]`
	// Accept all characters except non-" " whitespace characters (newlines, tabs)
	patternServiceDescription = `(?:[^\s]|[ ])`
	// REGEX builder with unit tests: https://regex101.com/r/5DPAiZ/1
	patternFullName    = `[\p{L}\p{Mn}\p{Pd}\'\x{2019} ]`
	patternDescription = `^[\p{L}\p{Mn}\p{Pd}\x{2019} [:punct:]0-9]{0,144}$`

	gcpServiceAccountEmailSuffix            = ".gserviceaccount.com"
	gcpUserManagedServiceAccountEmailSuffix = ".iam.gserviceaccount.com"
)

var (
	patternUniformName          = fmt.Sprintf(`%s{%d,%d}`, patternUniformNameCharacters, 1, uniformNameMaximumLength)
	whitelistUsername           = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s{%d,%d})$`, patternUniformNameCharacters, uniformNameMinimumLength, uniformNameMaximumLength))
	whitelistServiceID          = regexp.MustCompile(fmt.Sprintf(`(?i)^(s-%s{12})$`, patternAlphanumeric))
	whitelistServiceDescription = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s*)$`, patternServiceDescription))
	whitelistSecretName         = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s{%d,%d})$`, patternUniformNameCharacters, 1, uniformNameMaximumLength))
	whitelistRepoName           = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s{%d,%d})$`, patternUniformNameCharacters, 1, uniformNameMaximumLength))
	whitelistOrgName            = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s{%d,%d})$`, patternUniformNameCharacters, uniformNameMinimumLength, uniformNameMaximumLength))
	whitelistFullName           = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s{1,128})$`, patternFullName))
	whitelistDescription        = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s)$`, patternDescription))
	whitelistSetupCode          = regexp.MustCompile("^su-[a-zA-Z0-9-]{8,64}")

	whitelistAtLeastOneAlphanumeric = regexp.MustCompile(fmt.Sprintf("%s{1,}", patternAlphanumeric))

	whitelistOwnerInRepoPath    = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s\/.*)$`, patternUniformName))
	whitelistRepoNameInRepoPath = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s\/%s)$`, patternUniformName, patternUniformName))

	whitelistDirPathInDirPath  = regexp.MustCompile(fmt.Sprintf(`((?i)^(%s\/%s(\/%s)*)$)`, patternUniformName, patternUniformName, patternUniformName))
	whitelistNodeNameInDirPath = regexp.MustCompile(fmt.Sprintf(`(?i)^(([^\/]*\/)*%s)$`, patternUniformName))

	whitelistSecretNameInDirPath                 = regexp.MustCompile(fmt.Sprintf(`(?i)^(([^\/]*\/)*%s(?:\:.+)?)$`, patternUniformName))
	whitelistSecretPathInDirPath                 = regexp.MustCompile(fmt.Sprintf(`((?i)^(%s\/%s\/%s(\/%s)*(?:\:.+)?)$)`, patternUniformName, patternUniformName, patternUniformName, patternUniformName))
	whitelistSecretVersionIdentifierInSecretPath = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s)\/(%s)\/(%s\/)*(%s)(:(.+)?)$`, patternUniformName, patternUniformName, patternUniformName, patternUniformName))
	whitelistSecretVersionInSecretPath           = regexp.MustCompile(fmt.Sprintf(`(?i)^(%s)\/(%s)\/(%s\/)*(%s)(:([0-9]{1,9}|latest))$`, patternUniformName, patternUniformName, patternUniformName, patternUniformName))

	whitelistCredentialFingerprint = regexp.MustCompile("^[0-9a-fA-F]{1,64}$")
)

// Errors
var (
	ErrInvalidOrgName = errAPI.Code("invalid_org_name").StatusError(
		"organization names must be between 3 and 32 characters long and "+
			"may only contain letters, numbers, dashes (-), underscores (_), and dots (.)",
		http.StatusBadRequest,
	)
	ErrOrgNameMustContainAlphanumeric = errAPI.Code("org_name_must_contain_alphanumeric").StatusError(
		"organization names must contain at least one alphanumeric character ",
		http.StatusBadRequest,
	)
	ErrInvalidDescription = errAPI.Code("invalid_description").StatusError(
		"descriptions have a maximum length of 144 characters "+
			"and may only contain (special) letters, numbers, spaces, and punctuation characters",
		http.StatusBadRequest,
	)
	ErrInvalidBlindName     = errAPI.Code("invalid_blind_name").StatusError("The blind name is not a 256 bits string encoded with URL safe base64", http.StatusBadRequest)
	ErrInvalidDirPermission = errAPI.Code("invalid_dir_permission").StatusError(
		"directory permission may only consist of up to 3 unique letters r (read), w (write), and a (admin)",
		http.StatusBadRequest,
	)
	ErrInvalidDirRole = errAPI.Code("invalid_dir_role").StatusError(
		"directory roles must be either read, write, or admin",
		http.StatusBadRequest,
	)
	ErrInvalidCredentialFingerprint = errAPI.Code("invalid_credential_fingerprint").StatusError(
		"credential fingerprint must consist of 64 hexadecimal characters",
		http.StatusBadRequest,
	)

	ErrInvalidGCPServiceAccountEmail        = errAPI.Code("invalid_service_account_email").StatusError("not a valid GCP service account email", http.StatusBadRequest)
	ErrNotUserManagerGCPServiceAccountEmail = errAPI.Code("require_user_managed_service_account").StatusError("provided GCP service account email is not for a user-manager service account", http.StatusBadRequest)
	ErrInvalidGCPKMSResourceID              = errAPI.Code("invalid_key_resource_id").StatusError("not a valid resource ID, expected: projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY", http.StatusBadRequest)
	ErrInvalidSetupCode                     = errAPI.Code("invalid_setup_code").StatusError("setup code starts with su- and is followed by groups of letters and numbers separated by dashes", http.StatusBadRequest)
)

// ValidateNamespace validates a username.
func ValidateNamespace(namespace string) error {
	if ValidateUsername(namespace) != nil {
		return ErrInvalidNamespace
	}
	return nil
}

// ValidateAccountName validates an AcccountName.
func ValidateAccountName(name string) error {
	if AccountName(name).IsService() {
		return ValidateServiceID(name)
	}
	return ValidateUsername(name)
}

// ValidateUsername validates a username.
func ValidateUsername(username string) error {
	if !whitelistUsername.MatchString(username) {
		return ErrInvalidUsername
	}
	if !whitelistAtLeastOneAlphanumeric.MatchString(username) {
		return ErrUsernameMustContainAlphanumeric
	}
	if strings.HasPrefix(strings.ToLower(username), ServiceNamePrefix) {
		return ErrUsernameIsService
	}
	return nil
}

//ValidateFullName validates a user's full name.
func ValidateFullName(fullName string) error {
	if !whitelistFullName.MatchString(fullName) {
		return ErrInvalidFullName
	}
	return nil
}

// ValidateEmail validates an email address.
func ValidateEmail(email string) error {
	if govalidator.IsEmail(email) {
		return nil
	}
	return ErrInvalidEmail
}

// ValidateServiceID validates a service id.
func ValidateServiceID(serviceID string) error {
	if !whitelistServiceID.MatchString(serviceID) {
		return ErrInvalidServiceID
	}
	return nil
}

// ValidateServiceDescription validates a service description.
func ValidateServiceDescription(description string) error {
	if len(description) == 0 {
		return nil
	}

	// This check cannot be included in the regex, because Go does not allow higher repeat counts than 1000
	if len(description) > serviceDescriptionMaxLength {
		return ErrInvalidServiceDescription
	}

	if !whitelistServiceDescription.MatchString(description) {
		return ErrInvalidServiceDescription
	}
	return nil
}

// ValidateSecretName validates a secret name.
func ValidateSecretName(name string) error {
	if !whitelistSecretName.MatchString(name) {
		return ErrInvalidSecretName
	}
	if strings.Count(name, ".") == len(name) {
		return ErrInvalidSecretName
	}
	return nil
}

// ValidateOrgName validates an organization name.
func ValidateOrgName(name string) error {
	if !whitelistOrgName.MatchString(name) {
		return ErrInvalidOrgName
	}
	if !whitelistAtLeastOneAlphanumeric.MatchString(name) {
		return ErrOrgNameMustContainAlphanumeric
	}
	return nil
}

// ValidateOrgDescription validates an organization description.
func ValidateOrgDescription(description string) error {
	if !whitelistDescription.MatchString(description) {
		return ErrInvalidDescription
	}
	return nil
}

// ValidateRepoName validates a repo name.
func ValidateRepoName(name string) error {
	if !whitelistRepoName.MatchString(name) {
		return ErrInvalidRepoName
	}
	return nil
}

// ValidateBlindName validates a blind name.
func ValidateBlindName(blindName string) error {
	decodedString, err := base64.URLEncoding.DecodeString(blindName)
	if err != nil {
		return ErrInvalidBlindName
	}

	// 256 bits
	if len(decodedString) != blindNameByteSize {
		return ErrInvalidBlindName
	}

	return nil
}

// Validations of path work by validating the path in steps.
// 1. Validate the path before the object
// 1. Validate the object name
// 1. Validate any additions
//
// For example:
// /owner/repo/directory/subdirectory/secret:latest
// 1. Validate /owner/repo/directory/subdirectory/
// 1. Validate secret
// 1. Validate :latest

// ValidateRepoPath validates a repo path of form :owner/:repo_name
func ValidateRepoPath(path string) error {
	if !whitelistOwnerInRepoPath.MatchString(path) {
		return ErrInvalidRepoPath(path)
	}
	if !whitelistRepoNameInRepoPath.MatchString(path) {
		return ErrInvalidRepoName
	}
	return nil
}

// ValidateSecretPath validates a secret path of form :owner/:repo_name/:secretname
func ValidateSecretPath(path string) error {
	if !whitelistSecretNameInDirPath.MatchString(path) {
		return ErrInvalidSecretName
	}

	if !whitelistSecretPathInDirPath.MatchString(path) {
		return ErrInvalidSecretPath(path)
	}
	if whitelistSecretVersionIdentifierInSecretPath.MatchString(path) {
		if !whitelistSecretVersionInSecretPath.MatchString(path) {
			return ErrInvalidSecretVersion
		}
	}
	return nil
}

// ValidateDirPath validates a dir path of form :owner/:repo_name/[parents/]*:directory
func ValidateDirPath(path string) error {
	if !whitelistNodeNameInDirPath.MatchString(path) {
		return ErrInvalidDirName
	}

	if !whitelistDirPathInDirPath.MatchString(path) {
		return ErrInvalidDirPath(path)
	}

	return nil
}

// ValidateCredentialDescription validates the description for a credential.
func ValidateCredentialDescription(description string) error {
	if len(description) < 1 || len(description) > 32 {
		return ErrInvalidCredentialDescription
	}
	if !whitelistDescription.MatchString(description) {
		return ErrInvalidCredentialDescription
	}
	return nil
}

// ValidateCredentialFingerprint validates whether the given string is a valid credential fingerprint.
func ValidateCredentialFingerprint(fingerprint string) error {
	if !whitelistCredentialFingerprint.MatchString(fingerprint) {
		return ErrInvalidFingerprint
	}
	if len(fingerprint) != 64 {
		return ErrInvalidFingerprint
	}
	return nil
}

// ValidateShortCredentialFingerprint validates whether the given string can be used as a short version of a credential
// fingerprint.
func ValidateShortCredentialFingerprint(fingerprint string) error {
	if !whitelistCredentialFingerprint.MatchString(fingerprint) {
		return ErrInvalidFingerprint
	}
	if len(fingerprint) < ShortCredentialFingerprintMinimumLength {
		return ErrTooShortFingerprint
	}
	return nil
}

// ValidateGCPUserManagedServiceAccountEmail validates whether the given string is potentially a valid email for a
// user-managed GCP Service Account. The function does a best-effort check. If no error is returned, this does not mean
// the value is accepted by GCP.
func ValidateGCPUserManagedServiceAccountEmail(v string) error {
	if !govalidator.IsEmail(v) {
		return ErrInvalidGCPServiceAccountEmail
	}
	if !strings.HasSuffix(v, gcpServiceAccountEmailSuffix) {
		return ErrInvalidGCPServiceAccountEmail
	}
	if !strings.HasSuffix(v, gcpUserManagedServiceAccountEmailSuffix) {
		return ErrNotUserManagerGCPServiceAccountEmail
	}
	return nil
}

// ProjectIDFromGCPEmail returns the project ID included in the email of a GCP Service Account.
// If the input is not a valid user-managed GCP Service Account email, an error is returned.
func ProjectIDFromGCPEmail(in string) (string, error) {
	err := ValidateGCPUserManagedServiceAccountEmail(in)
	if err != nil {
		return "", err
	}

	spl := strings.Split(in, "@")
	if len(spl) != 2 {
		return "", errors.New("no @ in email")
	}
	return strings.TrimSuffix(spl[1], gcpUserManagedServiceAccountEmailSuffix), nil
}

// ValidateGCPKMSKeyResourceID validates whether the given string is potentially a valid resource ID for a GCP KMS key
// The function does a best-effort check. If no error is returned, this does not mean the value is accepted by GCP.
func ValidateGCPKMSKeyResourceID(v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return ErrInvalidGCPKMSResourceID
	}
	if u.Host != "" || u.Scheme != "" || u.Hostname() != "" || len(u.Query()) != 0 {
		return ErrInvalidGCPKMSResourceID
	}

	split := strings.Split(v, "/")
	if len(split) != 8 {
		return ErrInvalidGCPKMSResourceID
	}
	if split[0] != "projects" || split[2] != "locations" || split[4] != "keyRings" || split[6] != "cryptoKeys" {
		return ErrInvalidGCPKMSResourceID
	}

	return nil
}

// ValidateSetupCode checks whether the given string has the format of a valid setup code.
func ValidateSetupCode(code string) error {
	if !whitelistSetupCode.MatchString(code) {
		return ErrInvalidSetupCode
	}
	return nil
}
