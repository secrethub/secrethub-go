package api

import (
	"encoding/base64"
	"fmt"
	"strings"

	"bitbucket.org/zombiezen/cardcpx/natsort"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	ErrInvalidSecretPath       = errAPI.Code("invalid_secret_path").ErrorPref("secret path must be of the form <namespace>/<repo>[/<dir-path>]/<secret> got '%s'")
	ErrInvalidRepoPath         = errAPI.Code("invalid_repo_path").ErrorPref("repo path must be of the form <namespace>/<repo> got '%s'")
	ErrInvalidDirPath          = errAPI.Code("invalid_dir_path").ErrorPref("dir path must be of the form <namespace>/<repo>[/<dir-path>] got '%s'")
	ErrInvalidNamespace        = errAPI.Code("invalid_namespace").Error("namespace must be a valid username")
	ErrInvalidPath             = errAPI.Code("invalid_path").Error("path is not a reference to a namespace, a repository, a directory, or a secret")
	ErrInvalidPathType         = errAPI.Code("invalid_path_type").Error("using an unknown path type")
	ErrPathAlreadyHasVersion   = errAPI.Code("path_already_has_version").Error("this secret path already has a version")
	ErrPathHasNoVersion        = errAPI.Code("path_has_no_version").Error("this secret path requires a version")
	ErrParentPathOnInvalidPath = errAPI.Code("parent_path_on_invalid_path").ErrorPref("retrieving a parent path on an invalid path: %s")
)

var (
	pathSeparator    = "/"
	versionSeparator = ":"
)

// blindNameSize in bits
var blindNameByteSize = crypto.HMACSize

// BlindNamePath

// BlindNamePath represents a path that can be converted into a BlindName
// and exposes the necessary functions.
type BlindNamePath interface {
	// BlindName returns the blindname corresponding to this path.
	BlindName(key *crypto.SymmetricKey) (string, error)
	// GetRepoPath returns the RepoPath inside this BlindNamePath.
	GetRepoPath() RepoPath
}

// Path

// Path represents a path to either a namespace, a repo, a directory, or a secret
type Path string

// NewPath creates a new Path and validates whether it is valid
func NewPath(path string) (Path, error) {
	path = strings.TrimSuffix(path, pathSeparator)
	p := Path(path)
	err := p.Validate()
	return p, errio.Error(err)
}

// Validate checks whether the Path is either a valid SecretPath, DirPath, RepoPath or Namespace
func (p *Path) Validate() error {
	_, err := p.ToDirPath()
	if err == nil {
		return nil
	}

	_, err = p.ToSecretPath()
	if err == nil {
		return nil
	}
	_, err = p.ToRepoPath()
	if err == nil {
		return nil
	}
	_, err = p.ToNamespace()
	if err == nil {
		return nil
	}
	return ErrInvalidPath
}

// HasVersion returns if the path has a version.
// Only SecretPath has versions, so if has a version it is a SecretPath.
func (p Path) HasVersion() bool {
	return whitelistSecretVersionInSecretPath.MatchString(string(p))
}

// ToDirPath tries to convert the path to a valid DirPath
func (p Path) ToDirPath() (DirPath, error) {
	dp := DirPath(p)
	err := dp.Validate()
	return dp, err
}

// ToSecretPath tries to convert the Path to a valid SecretPath
func (p Path) ToSecretPath() (SecretPath, error) {
	sp := SecretPath(p)
	err := sp.Validate()
	return sp, err
}

// ToRepoPath tries to convert the Path to a valid RepoPath
func (p Path) ToRepoPath() (RepoPath, error) {
	rp := RepoPath(p)
	err := rp.Validate()
	return rp, err
}

// ToNamespace tries to convert the Path to a valid Namespace
func (p Path) ToNamespace() (Namespace, error) {
	ns := Namespace(p)
	err := ns.Validate()
	return ns, err
}

// Set implements the flag.Value interface and validates the value.
func (p *Path) Set(value string) error {
	path, err := NewPath(value)
	if err != nil {
		return err
	}
	*p = path
	return nil
}

// String converts the Path to a string
func (p Path) String() string {
	return string(p)
}

// SecretPath

// SecretPath is a custom type for secret paths of form :owner/:repo_name/:secret
type SecretPath string

// NewSecretPath formats a SecretPath from an owner, repo, and a secret.
func NewSecretPath(path string) (SecretPath, error) {
	path = strings.TrimSuffix(path, pathSeparator)
	p := SecretPath(path)
	err := p.Validate()
	return p, errio.Error(err)
}

// Validate validates a Secret path.
func (sp SecretPath) Validate() error {
	return ValidateSecretPath(string(sp))
}

// HasVersion returns whether there is a version specified in the path.
func (sp SecretPath) HasVersion() bool {
	return whitelistSecretVersionInSecretPath.MatchString(string(sp))
}

// AddVersion adds a version to a SecretPath and returns this path.
func (sp SecretPath) AddVersion(version int) (SecretPath, error) {
	if sp.HasVersion() {
		return SecretPath(""), ErrPathAlreadyHasVersion
	}

	p := SecretPath(fmt.Sprintf("%s:%d", sp.String(), version))
	err := p.Validate()
	if err != nil {
		return SecretPath(""), err
	}

	return p, nil
}

// GetVersion gets the version from the path.
func (sp SecretPath) GetVersion() (string, error) {
	if !sp.HasVersion() {
		return "", ErrPathHasNoVersion
	}

	versionMatches := whitelistSecretVersionInSecretPath.FindStringSubmatch(string(sp))

	return strings.ToLower(versionMatches[len(versionMatches)-1]), nil
}

// GetSecret gets the secret name from the path.
func (sp SecretPath) GetSecret() string {
	splits := strings.Split(string(sp), pathSeparator)
	splits = strings.Split(splits[len(splits)-1], versionSeparator)
	return splits[0]
}

// GetRepo returns the repo name in the SecretPath.
func (sp SecretPath) GetRepo() string {
	return getRepo(string(sp))
}

// BlindName converts a SecretPath to a blindname.
// BlindName ignores the Secret Version.
func (sp SecretPath) BlindName(key *crypto.SymmetricKey) (string, error) {
	secretBlindName := sp.String()
	if sp.HasVersion() {
		secretBlindName = strings.Split(secretBlindName, versionSeparator)[0]
	}
	return blindName(key, secretBlindName)
}

// GetRepoPath gets the RepoPath from the SecretPath.
// This function only works on validated SecretPaths.
func (sp SecretPath) GetRepoPath() RepoPath {
	return getRepoPath(sp.String())
}

// GetParentPath gets the DirPath from the SecretPath.
func (sp SecretPath) GetParentPath() (ParentPath, error) {
	err := sp.Validate()
	if err != nil {
		return ParentPath(""), ErrParentPathOnInvalidPath(err)
	}

	return getParentPath(sp.String()), nil
}

// GetNamespace returns the namespace in the SecretPath.
func (sp SecretPath) GetNamespace() string {
	return getNamespace(string(sp))
}

// Set implements the flag.Value interface and validates the value.
func (sp *SecretPath) Set(value string) error {
	path, err := NewSecretPath(value)
	if err != nil {
		return err
	}
	*sp = path
	return nil
}

// String returns the secret path as a string to be used for printing.
func (sp SecretPath) String() string {
	return string(sp)
}

// Value returns the secret path as a string to be used in communication
// with the client and in transportation to the server.
func (sp SecretPath) Value() string {
	return string(sp)
}

// DirPath

// DirPath is a parse for dir paths of form :owner/:repo_name/[parents/]*:directory
type DirPath ParentPath

// NewDirPath formats a RepoPath from an owner, repo string.
func NewDirPath(path string) (DirPath, error) {
	path = strings.TrimSuffix(path, pathSeparator)
	p := DirPath(path)
	err := p.Validate()
	return p, errio.Error(err)
}

// Validate validates a dir path of form :owner/:repo_name/[parents/]*:directory
func (dp DirPath) Validate() error {
	return ValidateDirPath(string(dp))
}

// HasParentDirectory returns if the DirPath has a parent directory.
func (dp DirPath) HasParentDirectory() bool {
	splits := strings.Split(string(dp), pathSeparator)
	return len(splits) > 2
}

// GetDirName returns the dir name.
func (dp DirPath) GetDirName() string {
	splits := strings.Split(string(dp), pathSeparator)
	return splits[len(splits)-1]
}

// GetRepo returns the name of the Repo.
func (dp DirPath) GetRepo() string {
	return getRepo(string(dp))
}

// BlindName returns the blind name of the DirPath.
func (dp DirPath) BlindName(key *crypto.SymmetricKey) (string, error) {
	return blindName(key, dp.String())
}

// GetRepoPath returns the namespace and repo name of the Repo.
func (dp DirPath) GetRepoPath() RepoPath {
	return getRepoPath(dp.String())
}

// IsRepoPath returns if the dir path is on repo level.
func (dp DirPath) IsRepoPath() bool {
	pathString := dp.String()
	return getRepoPath(pathString).String() == pathString
}

// GetParentPath returns the parent of the directory.
func (dp DirPath) GetParentPath() (ParentPath, error) {
	err := dp.Validate()
	if err != nil {
		return ParentPath(""), ErrParentPathOnInvalidPath(err)
	}

	return getParentPath(dp.String()), nil
}

// JoinDir constructs a new DirPath combined by the dirPath and dirName.
func (dp DirPath) JoinDir(dirName string) DirPath {
	return DirPath(joinPath(dp.String(), dirName))
}

// JoinSecret constructs a new SecretPath combined by the dirPath and dirName.
func (dp DirPath) JoinSecret(secretName string) SecretPath {
	return SecretPath(joinPath(dp.String(), secretName))
}

// GetNamespace returns the namespace of the Repo.
func (dp DirPath) GetNamespace() string {
	return getNamespace(string(dp))
}

// Set implements the flag.Value interface and validates the value.
func (dp *DirPath) Set(value string) error {
	path, err := NewDirPath(value)
	if err != nil {
		return err
	}
	*dp = path
	return nil
}

// String returns the dir path as a string to be used for printing.
func (dp DirPath) String() string {
	return string(dp)
}

// Value returns the dir path as a string to be used in communication
// with the client and in transportation to the server.
func (dp DirPath) Value() string {
	return string(dp)
}

// SortDirPaths makes a slice of dir paths sortable.
type SortDirPaths []DirPath

func (s SortDirPaths) Len() int {
	return len(s)
}

func (s SortDirPaths) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortDirPaths) Less(i, j int) bool {
	return natsort.Less(string(s[i]), string(s[j]))
}

// ParentPath

// ParentPath is a path to a namespace, repo or directory.
// This is used for generic blind name generation.
type ParentPath Path

func (pp ParentPath) String() string {
	return string(pp)
}

// BlindName generates the BlindName of the ParentPath.
func (pp ParentPath) BlindName(key *crypto.SymmetricKey) (string, error) {
	return blindName(key, pp.String())
}

// GetRepoPath returns the RepoPath of the ParentPath.
func (pp ParentPath) GetRepoPath() RepoPath {
	return getRepoPath(pp.String())
}

// HasParentPath checks if the ParentPath has a path or if it is the repo path.
func (pp ParentPath) HasParentPath() bool {
	err := RepoPath(pp).Validate()
	return err != nil
}

// JoinDir constructs a new DirPath combined by the ParentPath and dirName.
func (pp ParentPath) JoinDir(dirName string) DirPath {
	return DirPath(joinPath(pp.String(), dirName))
}

// RepoPath

// RepoPath is a parse for repo paths of form :owner/:repo_name
type RepoPath ParentPath

// NewRepoPath formats a RepoPath from an owner and repo.
func NewRepoPath(path string) (RepoPath, error) {
	path = strings.TrimSuffix(path, pathSeparator)
	p := RepoPath(path)
	err := p.Validate()
	return p, errio.Error(err)
}

// Validate validates a repo path of form :owner/:repo_name
func (rp RepoPath) Validate() error {
	return ValidateRepoPath(string(rp))
}

// BlindName returns the blind name of the DirPath.
func (rp RepoPath) BlindName(key *crypto.SymmetricKey) (string, error) {
	return blindName(key, rp.String())
}

// GetRepoPath gets the RepoPath from the RepoPath.
// This function only works on validated RepoPaths.
// This is necessary to implement BlindNamePath interface.
func (rp RepoPath) GetRepoPath() RepoPath {
	return getRepoPath(rp.String())
}

// GetDirPath converts this repoPath into a DirPath.
// This should be valid.
func (rp RepoPath) GetDirPath() DirPath {
	return DirPath(rp.String())
}

// GetRepo returns the name of the Repo.
func (rp RepoPath) GetRepo() string {
	return getRepo(string(rp))
}

// GetNamespace returns the namespace of the Repo.
func (rp RepoPath) GetNamespace() string {
	return getNamespace(string(rp))
}

// GetNamespaceAndRepoName returns the namespace and repo name of the Repo.
func (rp RepoPath) GetNamespaceAndRepoName() (string, string) {
	return rp.GetNamespace(), rp.GetRepo()
}

// Set implements the flag.Value interface and validates the value.
func (rp *RepoPath) Set(value string) error {
	path, err := NewRepoPath(value)
	if err != nil {
		return err
	}
	*rp = path
	return nil
}

// String returns the repository's path as a string to be used for printing.
func (rp RepoPath) String() string {
	return string(rp)
}

// Value returns the repository's path as a string to be used in communication
// with the client and in transportation to the server.
func (rp RepoPath) Value() string {
	return string(rp)
}

// Namespace

// Namespace represents a namespace
type Namespace ParentPath

// Set implements the flag.Value interface and validates the value.
func (n *Namespace) Set(value string) error {
	namespace := Namespace(value)
	err := namespace.Validate()
	if err != nil {
		return errio.Error(err)
	}
	*n = namespace
	return nil
}

// String returns the namespace as a string to be used for printing.
func (n Namespace) String() string {
	return string(n)
}

// Value returns the namespace as a string to be used in communication
// with the client and in transportation to the server.
func (n Namespace) Value() string {
	return string(n)
}

// Validate verifies whether the Namespace is valid
func (n Namespace) Validate() error {
	return ValidateNamespace(string(n))
}

// getRepo is a helper function that retrieves from path a repo.
// The path should be a validated SecretPath, DirPath or RepoPath.
func getRepo(path string) string {
	return strings.Split(path, pathSeparator)[1]
}

// getRepoPath is a helper function that retrieves from path a RepoPath.
// The path should be a validated SecretPath, DirPath or RepoPath.
func getRepoPath(path string) RepoPath {
	parts := strings.Split(path, pathSeparator)
	return RepoPath(parts[0] + pathSeparator + parts[1])
}

// getNamespace is a helper function that retrieves from path a namespace.
// The path should be a validated SecretPath, DirPath or RepoPath.
func getNamespace(path string) string {
	return strings.Split(path, pathSeparator)[0]
}

// getParentPath is a helper function that retrieves the ParentPath from a path
func getParentPath(path string) ParentPath {
	lastIndex := strings.LastIndexByte(path, []byte(pathSeparator)[0])
	return ParentPath(path[:lastIndex])
}

// blindName is a helper function that converts a path to a blind name.
// It converts the path to lowercase and performs an HMAC to form a case insensitive blind name.
// The name is outputted in base64 url safe encoding.
func blindName(key *crypto.SymmetricKey, path string) (string, error) {
	pathBytes := []byte(strings.ToLower(path))
	hmac, err := key.HMAC(pathBytes)
	if err != nil {
		return "", errio.Error(err)
	}
	return base64.URLEncoding.EncodeToString(hmac), nil
}

func joinPath(path, name string) string {
	return fmt.Sprintf("%s%s%s", path, pathSeparator, name)
}

// OrgName

// OrgName is the name of an organization.
type OrgName Namespace

// Set implements the flag.Value interface and validates the value.
func (n *OrgName) Set(value string) error {
	err := ValidateOrgName(value)
	if err != nil {
		return errio.Error(err)
	}
	*n = OrgName(value)
	return nil
}

// String returns the organisation's name as a string to be used for printing.
func (n OrgName) String() string {
	return string(n)
}

// Value returns the organisation's name as a string to be used in communication
// with the client and in transportation to the server.
func (n OrgName) Value() string {
	return string(n)
}

// Namespace returns the OrgName as a Namespace.
func (n OrgName) Namespace() Namespace {
	return Namespace(n)
}

// JoinPaths joins any number of path elements into a single path.
func JoinPaths(components ...string) string {
	var processed []string
	for _, c := range components {
		trimmed := strings.Trim(c, pathSeparator)
		if trimmed != "" {
			processed = append(processed, trimmed)
		}
	}
	return strings.Join(processed, pathSeparator)
}
