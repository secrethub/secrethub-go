package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/op/go-logging"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/errio"
)

var (
	log = logging.MustGetLogger("log")

	errHTTP = errio.Namespace("http")

	ErrClientTimeout = errHTTP.Code("timeout").Error("client timed out during request. Please try again.")
	ErrRequestFailed = errHTTP.Code("request_failed").ErrorPref("request to API server failed: %v")
)

const (
	baseURLPath = "/v1"

	pathAuthenticate = "%s/auth"

	// Current account
	pathMeUser              = "%s/me/user"
	pathMeRepos             = "%s/me/repos"
	pathMeKey               = "%s/me/key?key_version=v2"
	pathMeEmailVerification = "%s/me/user/verification-email"

	// Account
	pathAccount          = "%s/account/%s"
	pathCreateAccountKey = "%s/me/credentials/%s/key"

	// Users
	pathUsers = "%s/users"
	pathUser  = "%s/users/%s"

	// Repositories
	pathRepos          = "%s/namespaces/%s/repos"
	pathRepo           = "%s/namespaces/%s/repos/%s"
	pathRepoDirs       = "%s/namespaces/%s/repos/%s/dirs"
	pathRepoKey        = "%s/namespaces/%s/repos/%s/keys"
	pathRepoAccounts   = "%s/namespaces/%s/repos/%s/accounts"
	pathRepoEvents     = "%s/namespaces/%s/repos/%s/events"
	pathRepoDirSecrets = "%s/namespaces/%s/repos/%s/dirs/%s/secrets"
	pathRepoUsers      = "%s/namespaces/%s/repos/%s/users"
	pathRepoUser       = "%s/namespaces/%s/repos/%s/users/%s"
	pathServices       = "%s/namespaces/%s/repos/%s/services"
	pathService        = "%s/services/%s"

	// Dirs
	pathDir         = "%s/dirs/%s"
	pathDirAccounts = "%s/dirs/%s/accounts"

	// Secrets
	pathSecret         = "%s/secrets/%s"
	pathSecretVersions = "%s/secrets/%s/versions"
	pathSecretVersion  = "%s/secrets/%s/versions/%s"
	pathSecretKey      = "%s/secrets/%s/key"
	pathSecretKeys     = "%s/secrets/%s/keys"
	pathSecretEvents   = "%s/secrets/%s/events"

	// Dirs
	pathDirPermission = "%s/dirs/%s/permissions/%s"
	pathDirRules      = "%s/dirs/%s/rules"
	pathDirRule       = "%s/dirs/%s/rules/%s"

	// Organizations
	pathOrgs       = "%s/orgs"
	pathOrg        = "%s/orgs/%s"
	pathOrgMembers = "%s/orgs/%s/members"
	pathOrgMember  = "%s/orgs/%s/members/%s"
)

const (
	// DefaultServerURL defines the default SecretHub API endpoint.
	DefaultServerURL = "https://api.secrethub.io"
	// DefaultTimeout defines the default client http timeout.
	DefaultTimeout = time.Second * 30
)

// Client is a raw client for the SecretHub HTTP API.
// This client just makes HTTP calls, use secrethub.Client for a user-friendly client that can decrypt secrets and more.
type Client struct {
	client        *http.Client
	authenticator auth.Authenticator
	base          string // base url
	version       string
}

// NewClient configures a new Client and applies the provided ClientOptions.
func NewClient(with ...ClientOption) *Client {
	timeout := DefaultTimeout

	client := &Client{
		client: &http.Client{
			Timeout: timeout,
		},
		base: getBaseURL(DefaultServerURL),
		//version: secrethub.ClientVersion,
	}
	client.Options(with...)
	return client
}

// Options applies the provided options to an existing client.
func (c *Client) Options(with ...ClientOption) {
	for _, option := range with {
		option(c)
	}
}

// CreateSession tries to create a new session that can be used for temporary authentication to the SecretHub API.
func (c *Client) CreateSession(in interface{}) (*api.Session, error) {
	var out api.Session
	rawURL := fmt.Sprintf(pathAuthenticate, c.base)
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return &out, errio.Error(err)
}

// ME

// ListMyRepos gets a list of repos from SecretHub
func (c *Client) ListMyRepos() ([]*api.Repo, error) {
	out := []*api.Repo{}
	rawURL := fmt.Sprintf(pathMeRepos, c.base)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// CreateAccountKey creates a new account key encrypted by the credential with the given fingerprint.
func (c *Client) CreateAccountKey(in *api.CreateAccountKeyRequest, fingerprint string) (*api.EncryptedAccountKey, error) {
	out := &api.EncryptedAccountKey{}
	rawURL := fmt.Sprintf(pathCreateAccountKey, c.base, fingerprint)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetAccountKey returns the account's intermediate key encrypted with the key identified by key_identifier
func (c *Client) GetAccountKey() (*api.EncryptedAccountKey, error) {
	out := &api.EncryptedAccountKey{}
	rawURL := fmt.Sprintf(pathMeKey, c.base)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetMyUser gets the account's user.
func (c *Client) GetMyUser() (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathMeUser, c.base)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// SendVerificationEmail sends an email to the users registered email address for them to prove they
// own that email address.
func (c *Client) SendVerificationEmail() error {
	rawURL := fmt.Sprintf(pathMeEmailVerification, c.base)
	return c.post(rawURL, http.StatusCreated, nil, nil)
}

// Accounts

// GetAccount returns the account for a name
func (c *Client) GetAccount(name api.AccountName) (*api.Account, error) {
	out := &api.Account{}
	rawURL := fmt.Sprintf(pathAccount, c.base, name)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// USERS

// SignupUser creates a new user at SecretHub
func (c *Client) SignupUser(in *api.CreateUserRequest) (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathUsers, c.base)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetUser gets a user by its username from SecretHub
func (c *Client) GetUser(username string) (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathUser, c.base, username)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// REPOSITORIES

// GetRepo gets a repo by its namespace and repo name
func (c *Client) GetRepo(namespace, repoName string) (*api.Repo, error) {
	out := &api.Repo{}
	rawURL := fmt.Sprintf(pathRepo, c.base, namespace, repoName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListRepos lists all repos in the given namespace.
func (c *Client) ListRepos(namespace string) ([]*api.Repo, error) {
	out := []*api.Repo{}
	rawURL := fmt.Sprintf(pathRepos, c.base, namespace)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// CreateRepo  creates a new repo at SecretHub
func (c *Client) CreateRepo(namespace string, in *api.CreateRepoRequest) (*api.Repo, error) {
	out := &api.Repo{}
	rawURL := fmt.Sprintf(pathRepos, c.base, namespace)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetRepoKeys retrieves the repo key of the user.
func (c *Client) GetRepoKeys(namespace, repoName string) (*api.RepoKeys, error) {
	out := &api.RepoKeys{}
	rawURL := fmt.Sprintf(pathRepoKey, c.base, namespace, repoName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// DeleteRepo deletes a repo
func (c *Client) DeleteRepo(namespace, repoName string) error {
	rawURL := fmt.Sprintf(pathRepo, c.base, namespace, repoName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// AuditRepo gets the audit events for a given repo.
func (c *Client) AuditRepo(namespace, repoName string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	out := []*api.Audit{}
	rawURL := fmt.Sprintf(pathRepoEvents+"?subject_types=%s", c.base, namespace, repoName, subjectTypes.Join(","))
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// ListRepoAccounts lists the accounts of a repo.
func (c *Client) ListRepoAccounts(namespace, repoName string) ([]*api.Account, error) {
	out := []*api.Account{}
	rawURL := fmt.Sprintf(pathRepoAccounts, c.base, namespace, repoName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// REPO USERS

// InviteRepo adds a user to a repo.
func (c *Client) InviteRepo(namespace, repoName string, in *api.InviteUserRequest) (*api.RepoMember, error) {
	out := &api.RepoMember{}
	rawURL := fmt.Sprintf(pathRepoUsers, c.base, namespace, repoName)
	err := c.post(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// GetRepoUser retrieves a user for a repo.
// If the user is a repo member, then the user is retrieved.
func (c *Client) GetRepoUser(namespace, repoName, username string) (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathRepoUser, c.base, namespace, repoName, username)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// RemoveUser removes a user from a repo.
func (c *Client) RemoveUser(namespace, repoName, username string) (*api.RevokeRepoResponse, error) {
	out := &api.RevokeRepoResponse{}
	rawURL := fmt.Sprintf(pathRepoUser, c.base, namespace, repoName, username)
	err := c.delete(rawURL, out)
	return out, errio.Error(err)
}

// ListRepoUsers lists the users of a repo.
func (c *Client) ListRepoUsers(namespace, repoName string) ([]*api.User, error) {
	out := []*api.User{}
	rawURL := fmt.Sprintf(pathRepoUsers, c.base, namespace, repoName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// Service

// CreateService creates a new service for a repo.
func (c *Client) CreateService(namespace, repoName string, in *api.CreateServiceRequest) (*api.Service, error) {
	out := &api.Service{}
	rawURL := fmt.Sprintf(pathServices, c.base, namespace, repoName)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetService retrieves a service.
func (c *Client) GetService(service string) (*api.Service, error) {
	out := &api.Service{}
	rawURL := fmt.Sprintf(pathService, c.base, service)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// DeleteService deletes an service.
func (c *Client) DeleteService(service string) (*api.RevokeRepoResponse, error) {
	out := &api.RevokeRepoResponse{}
	rawURL := fmt.Sprintf(pathService, c.base, service)
	err := c.delete(rawURL, out)
	return out, errio.Error(err)
}

// ListServices lists the services for a repo.
func (c *Client) ListServices(namespace, repoName string) ([]*api.Service, error) {
	out := []*api.Service{}
	rawURL := fmt.Sprintf(pathServices, c.base, namespace, repoName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DIRS

// CreateDir creates a new directory in the repo.
func (c *Client) CreateDir(namespace, repoName string, in *api.CreateDirRequest) (*api.EncryptedDir, error) {
	rawURL := fmt.Sprintf(pathRepoDirs, c.base, namespace, repoName)
	out := &api.EncryptedDir{}
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return out, errio.Error(err)
}

// GetTree gets a directory and all of it subdirs and secrets recursively by blind name.
// If depth is > 0 then the result is limited to depth
// If ancestors = true then ancestors are added.
func (c *Client) GetTree(dirBlindName string, depth int, ancestor bool) (*api.EncryptedTree, error) {
	rawURL := fmt.Sprintf(pathDir, c.base, dirBlindName)
	rawURL = fmt.Sprintf(rawURL+"?depth=%d&ancestors=%v", depth, ancestor)
	out := &api.EncryptedTree{}
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListDirAccounts returns all accounts with read access.
func (c *Client) ListDirAccounts(dirBlindName string) ([]*api.Account, error) {
	out := []*api.Account{}
	rawURL := fmt.Sprintf(pathDirAccounts, c.base, dirBlindName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteDir deletes a directory by blind name.
func (c *Client) DeleteDir(dirBlindName string) error {
	rawURL := fmt.Sprintf(pathDir, c.base, dirBlindName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// ACL

// CreateAccessRule creates an AccessRule.
func (c *Client) CreateAccessRule(dirBlindName string, accountName api.AccountName, in *api.CreateAccessRuleRequest) (*api.AccessRule, error) {
	out := &api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.put(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// UpdateAccessRule updates an AccessRule.
func (c *Client) UpdateAccessRule(dirBlindName string, accountName api.AccountName, in *api.UpdateAccessRuleRequest) (*api.AccessRule, error) {
	out := &api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.patch(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// GetAccessLevel gets an access level for an account.
func (c *Client) GetAccessLevel(dirBlindName string, accountName api.AccountName) (*api.AccessLevel, error) {
	out := &api.AccessLevel{}
	rawURL := fmt.Sprintf(pathDirPermission, c.base, dirBlindName, accountName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetAccessRule gets an access rule for an account.
func (c *Client) GetAccessRule(dirBlindName string, accountName api.AccountName) (*api.AccessRule, error) {
	out := &api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListAccessRules gets the access rules for a given directory.
func (c *Client) ListAccessRules(dirBlindName string, depth int, withAncestors bool) ([]*api.AccessRule, error) {
	out := []*api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRules, c.base, dirBlindName)
	rawURL = fmt.Sprintf(rawURL+"?depth=%d&ancestors=%v", depth, withAncestors)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteAccessRule deletes an access rule for an account.
func (c *Client) DeleteAccessRule(dirBlindName string, accountName api.AccountName) error {
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// SECRETS

// CreateSecret writes a new secret.
func (c Client) CreateSecret(namespace, repoName, dirBlindName string, in *api.CreateSecretRequest) (*api.EncryptedSecretVersion, error) {
	rawURL := fmt.Sprintf(pathRepoDirSecrets, c.base, namespace, repoName, dirBlindName)
	out := &api.EncryptedSecretVersion{}
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return out, errio.Error(err)
}

// GetSecret gets a secret by its blind name.
// Note that this does not include the versions and secret data.
func (c *Client) GetSecret(secretBlindName string) (*api.EncryptedSecret, error) {
	out := &api.EncryptedSecret{}
	rawURL := fmt.Sprintf(pathSecret, c.base, secretBlindName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// CreateSecretVersion creates a new version of an existing secret.
func (c Client) CreateSecretVersion(blindName string, in *api.CreateSecretVersionRequest) (*api.EncryptedSecretVersion, error) {
	rawURL := fmt.Sprintf(pathSecretVersions, c.base, blindName)
	out := &api.EncryptedSecretVersion{}
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return out, errio.Error(err)
}

// ListSecretVersions lists all versions of a secret by its name.
func (c *Client) ListSecretVersions(secretBlindName string, withData bool) ([]*api.EncryptedSecretVersion, error) {
	out := []*api.EncryptedSecretVersion{}
	rawURL := fmt.Sprintf(pathSecretVersions+"?encrypted_blob=%t", c.base, secretBlindName, withData)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// GetSecretLatestVersion gets the latest version of the secret with the given blind name.
func (c *Client) GetSecretLatestVersion(secretBlindName string, withData bool) (*api.EncryptedSecretVersion, error) {
	out := &api.EncryptedSecretVersion{}
	rawURL := fmt.Sprintf(pathSecret+"?encrypted_blob=%t", c.base, secretBlindName, withData)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetSecretVersion gets a single version of a secret by its name.
func (c *Client) GetSecretVersion(secretBlindName string, version string, withData bool) (*api.EncryptedSecretVersion, error) {
	out := &api.EncryptedSecretVersion{}
	rawURL := fmt.Sprintf(pathSecretVersion+"?encrypted_blob=%t", c.base, secretBlindName, version, withData)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetCurrentSecretKey gets the secret key currently used for encrypting the secret.
func (c *Client) GetCurrentSecretKey(secretBlindName string) (*api.EncryptedSecretKey, error) {
	out := &api.EncryptedSecretKey{}
	rawURL := fmt.Sprintf(pathSecretKey, c.base, secretBlindName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// CreateSecretKey creates a new secret key.
func (c *Client) CreateSecretKey(secretBlindName string, in *api.CreateSecretKeyRequest) (*api.EncryptedSecretKey, error) {
	out := &api.EncryptedSecretKey{}
	rawURL := fmt.Sprintf(pathSecretKeys, c.base, secretBlindName)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// AuditSecret gets the audit events for a given secret.
func (c *Client) AuditSecret(secretBlindName string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	out := []*api.Audit{}
	rawURL := fmt.Sprintf(pathSecretEvents+"?subject_types=%s", c.base, secretBlindName, subjectTypes.Join(","))
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteSecret deletes a secret.
func (c *Client) DeleteSecret(secretBlindName string) error {
	rawURL := fmt.Sprintf(pathSecret, c.base, secretBlindName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// DeleteSecretVersion deletes a version of a secret.
func (c *Client) DeleteSecretVersion(secretBlindName string, version string) error {
	rawURL := fmt.Sprintf(pathSecretVersion, c.base, secretBlindName, version)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// ListSecretKeys lists an account's secret keys.
func (c *Client) ListSecretKeys(secretBlindName string) ([]*api.EncryptedSecretKey, error) {
	out := []*api.EncryptedSecretKey{}
	rawURL := fmt.Sprintf(pathSecretKeys, c.base, secretBlindName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// Orgs

// CreateOrg creates an organization.
func (c *Client) CreateOrg(in *api.CreateOrgRequest) (*api.Org, error) {
	out := &api.Org{}
	rawURL := fmt.Sprintf(pathOrgs, c.base)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetOrg gets an organization's details.
func (c *Client) GetOrg(name string) (*api.Org, error) {
	out := &api.Org{}
	rawURL := fmt.Sprintf(pathOrg, c.base, name)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListMyOrgs lists the organizations an account is a member of.
func (c *Client) ListMyOrgs() ([]*api.Org, error) {
	out := []*api.Org{}
	rawURL := fmt.Sprintf(pathOrgs, c.base)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteOrg permanently deletes an organization and all of its resources.
func (c *Client) DeleteOrg(name string) error {
	rawURL := fmt.Sprintf(pathOrg, c.base, name)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// ListOrgMembers lists an organization's members.
func (c *Client) ListOrgMembers(name string) ([]*api.OrgMember, error) {
	out := []*api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMembers, c.base, name)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// GetOrgMember gets a  user's organization membership details.
func (c *Client) GetOrgMember(name string, username string) (*api.OrgMember, error) {
	out := &api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMember, c.base, name, username)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// CreateOrgMember creates a new organization member.
func (c *Client) CreateOrgMember(name string, in *api.CreateOrgMemberRequest) (*api.OrgMember, error) {
	out := &api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMembers, c.base, name)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// UpdateOrgMember updates the role of the given username in the org with the given name.
func (c *Client) UpdateOrgMember(name string, username string, in *api.UpdateOrgMemberRequest) (*api.OrgMember, error) {
	out := &api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMember, c.base, name, username)
	err := c.post(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// RevokeOrgMember revokes an organization member.
func (c *Client) RevokeOrgMember(name string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	out := &api.RevokeOrgResponse{}
	rawURL := fmt.Sprintf(pathOrgMember, c.base, name, username)
	if opts != nil {
		values, err := opts.Values()
		if err != nil {
			return nil, errio.Error(err)
		}
		rawURL = fmt.Sprintf("%s?%s", rawURL, values.Encode())
	}
	err := c.delete(rawURL, out)
	return out, errio.Error(err)
}

// HELPER METHODS

// get is a helper function to make an http GET request.
func (c *Client) get(rawURL string, out interface{}) error {
	err := c.do(rawURL, "GET", http.StatusOK, nil, out)
	return errio.Error(err)
}

// post is a helper function to make an http POST request
func (c *Client) post(rawURL string, expectedStatus int, in interface{}, out interface{}) error {
	err := c.do(rawURL, "POST", expectedStatus, in, out)
	return errio.Error(err)
}

// put is a helper function to make an http PUT request.
func (c *Client) put(rawURL string, expectedStatus int, in interface{}, out interface{}) error {
	err := c.do(rawURL, "PUT", expectedStatus, in, out)
	return errio.Error(err)
}

// patch is a helper function to make an http PATCH request.
func (c *Client) patch(rawURL string, expectedStatus int, in interface{}, out interface{}) error {
	err := c.do(rawURL, "PATCH", expectedStatus, in, out)
	return errio.Error(err)
}

// delete is a helper function to make an http DELETE request.
func (c *Client) delete(rawURL string, out interface{}) error {
	err := c.do(rawURL, "DELETE", http.StatusOK, nil, out)
	return errio.Error(err)
}

// Helper function to make an http request. Parses the url, encodes in as the request body,
// executes an http request. If the server returns the wrong statuscode, we try to parse
// the error and return it. If everything went well, it decodes the response body into out.
func (c *Client) do(rawURL string, method string, expectedStatus int, in interface{}, out interface{}) error {
	uri, err := url.Parse(rawURL)
	if err != nil {
		return errio.Error(err)
	}

	req, err := http.NewRequest(method, uri.String(), nil)
	if err != nil {
		return errio.Error(err)
	}

	err = encodeRequest(req, in)
	if err != nil {
		return errio.Error(err)
	}

	if c.authenticator != nil {
		err = c.authenticator.Authenticate(req)
		if err != nil {
			return errio.Error(err)
		}
	}

	req.Header.Set("User-Agent", "SecretHub/"+c.version)

	resp, err := c.client.Do(req)
	if err != nil {
		urlErr := err.(*url.Error)
		if urlErr.Timeout() {
			return ErrClientTimeout
		}
		return ErrRequestFailed(urlErr.Error())
	}

	if resp.StatusCode == http.StatusUpgradeRequired {
		return errHTTP.Code("out_of_date").Errorf(
			"Client is out of date\n" +
				"Go to `https://secrethub.io/docs/getting-started/install` to see how to update your client.")
	} else if resp.StatusCode != expectedStatus {
		return parseError(resp)
	}

	err = decodeResponse(resp, out)
	if err != nil {
		return errio.StatusError(err)
	}

	return nil
}

func getBaseURL(serverURL string) string {
	return strings.TrimSuffix(serverURL, "/") + baseURLPath
}