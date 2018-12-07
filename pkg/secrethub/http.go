package secrethub

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub/core/errio"
	"github.com/keylockerbv/secrethub/core/httpio"
	logging "github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("log")

	// ClientVersion is the current version of the client
	// Has to be set by the compiler
	ClientVersion string
)

const (
	baseURLPath = "/v1"

	// Current account
	pathMeUser  = "%s/me/user"
	pathMeRepos = "%s/me/repos"
	pathMeKey   = "%s/me/key"

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
	DefaultTimeout = time.Second * 10
)

// ClientOptions define client options, overriding the default settings.
type ClientOptions struct {
	ServerURL string
	Timeout   time.Duration
}

// httpClient is a raw client for the SecretHub http API.
type httpClient struct {
	client     *http.Client
	credential Credential
	base       string // base url
	version    string
}

// newClient configures a new httpClient and overrides default values
// when opts is not nil.
func newClient(credential Credential, opts *ClientOptions) *httpClient {
	serverURL := DefaultServerURL
	timeout := DefaultTimeout
	if opts != nil {
		if opts.ServerURL != "" {
			serverURL = opts.ServerURL
		}

		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	serverURL = strings.TrimSuffix(serverURL, "/")
	serverURL = serverURL + baseURLPath

	return &httpClient{
		client: &http.Client{
			Timeout: timeout,
		},
		credential: credential,
		base:       serverURL,
		version:    ClientVersion,
	}
}

// ME

// ListMyRepos gets a list of repos from SecretHub
func (c *httpClient) ListMyRepos() ([]*api.Repo, error) {
	out := []*api.Repo{}
	rawURL := fmt.Sprintf(pathMeRepos, c.base)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

func (c *httpClient) CreateAccountKey(in *api.CreateAccountKeyRequest, fingerprint string) (*api.EncryptedAccountKey, error) {
	out := &api.EncryptedAccountKey{}
	rawURL := fmt.Sprintf(pathCreateAccountKey, c.base, fingerprint)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetAccountKey returns the account's intermediate key encrypted with the key identified by key_identifier
func (c *httpClient) GetAccountKey() (*api.EncryptedAccountKey, error) {
	out := &api.EncryptedAccountKey{}
	rawURL := fmt.Sprintf(pathMeKey, c.base)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetMyUser gets the account's user.
func (c *httpClient) GetMyUser() (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathMeUser, c.base)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// Accounts

// GetAccount returns the account for a name
func (c *httpClient) GetAccount(name api.AccountName) (*api.Account, error) {
	out := &api.Account{}
	rawURL := fmt.Sprintf(pathAccount, c.base, name)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// USERS

// SignupUser creates a new user at SecretHub
func (c *httpClient) SignupUser(in *api.CreateUserRequest) (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathUsers, c.base)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetUser gets a user by its username from SecretHub
func (c *httpClient) GetUser(username string) (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathUser, c.base, username)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// REPOSITORIES

// GetRepo gets a repo by its namespace and repo name
func (c *httpClient) GetRepo(namespace, repoName string) (*api.Repo, error) {
	out := &api.Repo{}
	rawURL := fmt.Sprintf(pathRepo, c.base, namespace, repoName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

func (c *httpClient) ListRepos(namespace string) ([]*api.Repo, error) {
	out := []*api.Repo{}
	rawURL := fmt.Sprintf(pathRepos, c.base, namespace)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// CreateRepo  creates a new repo at SecretHub
func (c *httpClient) CreateRepo(namespace string, in *api.CreateRepoRequest) (*api.Repo, error) {
	out := &api.Repo{}
	rawURL := fmt.Sprintf(pathRepos, c.base, namespace)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetRepoKeys retrieves the repo key of the user.
func (c *httpClient) GetRepoKeys(namespace, repoName string) (*api.RepoKeys, error) {
	out := &api.RepoKeys{}
	rawURL := fmt.Sprintf(pathRepoKey, c.base, namespace, repoName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// DeleteRepo deletes a repo
func (c *httpClient) DeleteRepo(namespace, repoName string) error {
	rawURL := fmt.Sprintf(pathRepo, c.base, namespace, repoName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// AuditRepo gets the audit events for a given repo.
func (c *httpClient) AuditRepo(namespace, repoName string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	out := []*api.Audit{}
	rawURL := fmt.Sprintf(pathRepoEvents+"?subject_types=%s", c.base, namespace, repoName, subjectTypes.Join(","))
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// ListRepoAccounts lists the accounts of a repo.
func (c *httpClient) ListRepoAccounts(namespace, repoName string) ([]*api.Account, error) {
	out := []*api.Account{}
	rawURL := fmt.Sprintf(pathRepoAccounts, c.base, namespace, repoName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// REPO USERS

// InviteRepo adds a user to a repo.
func (c *httpClient) InviteRepo(namespace, repoName string, in *api.InviteUserRequest) (*api.RepoMember, error) {
	out := &api.RepoMember{}
	rawURL := fmt.Sprintf(pathRepoUsers, c.base, namespace, repoName)
	err := c.post(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// GetRepoUser retrieves a user for a repo.
// If the user is a repo member, then the user is retrieved.
func (c *httpClient) GetRepoUser(namespace, repoName, username string) (*api.User, error) {
	out := &api.User{}
	rawURL := fmt.Sprintf(pathRepoUser, c.base, namespace, repoName, username)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// RemoveUser removes a user from a repo.
func (c *httpClient) RemoveUser(namespace, repoName, username string) (*api.RevokeRepoResponse, error) {
	out := &api.RevokeRepoResponse{}
	rawURL := fmt.Sprintf(pathRepoUser, c.base, namespace, repoName, username)
	err := c.delete(rawURL, out)
	return out, errio.Error(err)
}

// ListRepoUsers lists the users of a repo.
func (c *httpClient) ListRepoUsers(namespace, repoName string) ([]*api.User, error) {
	out := []*api.User{}
	rawURL := fmt.Sprintf(pathRepoUsers, c.base, namespace, repoName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// Service

// CreateService creates a new service for a repo.
func (c *httpClient) CreateService(namespace, repoName string, in *api.CreateServiceRequest) (*api.Service, error) {
	out := &api.Service{}
	rawURL := fmt.Sprintf(pathServices, c.base, namespace, repoName)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetServices retrieves a service.
func (c *httpClient) GetService(service string) (*api.Service, error) {
	out := &api.Service{}
	rawURL := fmt.Sprintf(pathService, c.base, service)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// DeleteService deletes an service.
func (c *httpClient) DeleteService(service string) (*api.RevokeRepoResponse, error) {
	out := &api.RevokeRepoResponse{}
	rawURL := fmt.Sprintf(pathService, c.base, service)
	err := c.delete(rawURL, out)
	return out, errio.Error(err)
}

// ListServices lists the services for a repo.
func (c *httpClient) ListServices(namespace, repoName string) ([]*api.Service, error) {
	out := []*api.Service{}
	rawURL := fmt.Sprintf(pathServices, c.base, namespace, repoName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DIRS

// CreateDir creates a new directory in the repo.
func (c *httpClient) CreateDir(namespace, repoName string, in *api.CreateDirRequest) (*api.EncryptedDir, error) {
	rawURL := fmt.Sprintf(pathRepoDirs, c.base, namespace, repoName)
	out := &api.EncryptedDir{}
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return out, errio.Error(err)
}

// GetTree gets a directory and all of it subdirs and secrets recursively by blind name.
// If depth is > 0 then the result is limited to depth
// If ancestors = true then ancestors are added.
func (c *httpClient) GetTree(dirBlindName string, depth int, ancestor bool) (*api.EncryptedTree, error) {
	rawURL := fmt.Sprintf(pathDir, c.base, dirBlindName)
	rawURL = fmt.Sprintf(rawURL+"?depth=%d&ancestors=%v", depth, ancestor)
	out := &api.EncryptedTree{}
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListDirAccounts returns all accounts with read access.
func (c *httpClient) ListDirAccounts(dirBlindName string) ([]*api.Account, error) {
	out := []*api.Account{}
	rawURL := fmt.Sprintf(pathDirAccounts, c.base, dirBlindName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteDir deletes a directory by blind name.
func (c *httpClient) DeleteDir(dirBlindName string) error {
	rawURL := fmt.Sprintf(pathDir, c.base, dirBlindName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// ACL

// CreateAccessRule creates an AccessRule.
func (c *httpClient) CreateAccessRule(dirBlindName string, accountName api.AccountName, in *api.CreateAccessRuleRequest) (*api.AccessRule, error) {
	out := &api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.put(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// UpdateAccessRule updates an AccessRule.
func (c *httpClient) UpdateAccessRule(dirBlindName string, accountName api.AccountName, in *api.UpdateAccessRuleRequest) (*api.AccessRule, error) {
	out := &api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.patch(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// GetAccessLevel gets an access level for an account.
func (c *httpClient) GetAccessLevel(dirBlindName string, accountName api.AccountName) (*api.AccessLevel, error) {
	out := &api.AccessLevel{}
	rawURL := fmt.Sprintf(pathDirPermission, c.base, dirBlindName, accountName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetAccessRule gets an access rule for an account.
func (c *httpClient) GetAccessRule(dirBlindName string, accountName api.AccountName) (*api.AccessRule, error) {
	out := &api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListAccessRules gets the access rules for a given directory.
func (c *httpClient) ListAccessRules(dirBlindName string, depth int, withAncestors bool) ([]*api.AccessRule, error) {
	out := []*api.AccessRule{}
	rawURL := fmt.Sprintf(pathDirRules, c.base, dirBlindName)
	rawURL = fmt.Sprintf(rawURL+"?depth=%d&ancestors=%v", depth, withAncestors)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteAccessRule deletes an access rule for an account.
func (c *httpClient) DeleteAccessRule(dirBlindName string, accountName api.AccountName) error {
	rawURL := fmt.Sprintf(pathDirRule, c.base, dirBlindName, accountName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// SECRETS

// CreateSecret writes a new secret.
func (c httpClient) CreateSecret(namespace, repoName, dirBlindName string, in *api.CreateSecretRequest) (*api.EncryptedSecretVersion, error) {
	rawURL := fmt.Sprintf(pathRepoDirSecrets, c.base, namespace, repoName, dirBlindName)
	out := &api.EncryptedSecretVersion{}
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return out, errio.Error(err)
}

// GetSecret gets a secret by its blind name.
// Note that this does not include the versions and secret data.
func (c *httpClient) GetSecret(secretBlindName string) (*api.EncryptedSecret, error) {
	out := &api.EncryptedSecret{}
	rawURL := fmt.Sprintf(pathSecret, c.base, secretBlindName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// CreateSecretVersion creates a new version of an existing secret.
func (c httpClient) CreateSecretVersion(blindName string, in *api.CreateSecretVersionRequest) (*api.EncryptedSecretVersion, error) {
	rawURL := fmt.Sprintf(pathSecretVersions, c.base, blindName)
	out := &api.EncryptedSecretVersion{}
	err := c.post(rawURL, http.StatusCreated, in, &out)
	return out, errio.Error(err)
}

// ListSecretVersions lists all versions of a secret by its name.
func (c *httpClient) ListSecretVersions(secretBlindName string, withData bool) ([]*api.EncryptedSecretVersion, error) {
	out := []*api.EncryptedSecretVersion{}
	rawURL := fmt.Sprintf(pathSecretVersions+"?encrypted_blob=%t", c.base, secretBlindName, withData)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// GetSecret gets a single secret by its name.
func (c *httpClient) GetSecretLatestVersion(secretBlindName string, withData bool) (*api.EncryptedSecretVersion, error) {
	out := &api.EncryptedSecretVersion{}
	rawURL := fmt.Sprintf(pathSecret+"?encrypted_blob=%t", c.base, secretBlindName, withData)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetSecretVersion gets a single version of a secret by its name.
func (c *httpClient) GetSecretVersion(secretBlindName string, version string, withData bool) (*api.EncryptedSecretVersion, error) {
	out := &api.EncryptedSecretVersion{}
	rawURL := fmt.Sprintf(pathSecretVersion+"?encrypted_blob=%t", c.base, secretBlindName, version, withData)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// GetCurrentSecretKey gets the secret key currently used for encrypting the secret.
func (c *httpClient) GetCurrentSecretKey(secretBlindName string) (*api.EncryptedSecretKey, error) {
	out := &api.EncryptedSecretKey{}
	rawURL := fmt.Sprintf(pathSecretKey, c.base, secretBlindName)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// CreateSecretKey creates a new secret key.
func (c *httpClient) CreateSecretKey(secretBlindName string, in *api.CreateSecretKeyRequest) (*api.EncryptedSecretKey, error) {
	out := &api.EncryptedSecretKey{}
	rawURL := fmt.Sprintf(pathSecretKeys, c.base, secretBlindName)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// AuditSecret gets the audit events for a given secret.
func (c *httpClient) AuditSecret(secretBlindName string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	out := []*api.Audit{}
	rawURL := fmt.Sprintf(pathSecretEvents+"?subject_types=%s", c.base, secretBlindName, subjectTypes.Join(","))
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteSecret deletes a secret.
func (c *httpClient) DeleteSecret(secretBlindName string) error {
	rawURL := fmt.Sprintf(pathSecret, c.base, secretBlindName)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// DeleteSecretVersion deletes a version of a secret.
func (c *httpClient) DeleteSecretVersion(secretBlindName string, version string) error {
	rawURL := fmt.Sprintf(pathSecretVersion, c.base, secretBlindName, version)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// ListSecretKeys lists an account's secret keys.
func (c *httpClient) ListSecretKeys(secretBlindName string) ([]*api.EncryptedSecretKey, error) {
	out := []*api.EncryptedSecretKey{}
	rawURL := fmt.Sprintf(pathSecretKeys, c.base, secretBlindName)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// Orgs

// CreateOrg creates an organization.
func (c *httpClient) CreateOrg(in *api.CreateOrgRequest) (*api.Org, error) {
	out := &api.Org{}
	rawURL := fmt.Sprintf(pathOrgs, c.base)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

// GetOrg gets an organization's details.
func (c *httpClient) GetOrg(name string) (*api.Org, error) {
	out := &api.Org{}
	rawURL := fmt.Sprintf(pathOrg, c.base, name)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// ListMyOrgs lists the organizations an account is a member of.
func (c *httpClient) ListMyOrgs() ([]*api.Org, error) {
	out := []*api.Org{}
	rawURL := fmt.Sprintf(pathOrgs, c.base)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// DeleteOrg permanently deletes an organization and all of its resources.
func (c *httpClient) DeleteOrg(name string) error {
	rawURL := fmt.Sprintf(pathOrg, c.base, name)
	err := c.delete(rawURL, nil)
	return errio.Error(err)
}

// ListOrgMembers lists an organization's members.
func (c *httpClient) ListOrgMembers(name string) ([]*api.OrgMember, error) {
	out := []*api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMembers, c.base, name)
	err := c.get(rawURL, &out)
	return out, errio.Error(err)
}

// GetOrgMember gets a  user's organization membership details.
func (c *httpClient) GetOrgMember(name string, username string) (*api.OrgMember, error) {
	out := &api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMember, c.base, name, username)
	err := c.get(rawURL, out)
	return out, errio.Error(err)
}

// CreateOrgMember creates a new organization member.
func (c *httpClient) CreateOrgMember(name string, in *api.CreateOrgMemberRequest) (*api.OrgMember, error) {
	out := &api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMembers, c.base, name)
	err := c.post(rawURL, http.StatusCreated, in, out)
	return out, errio.Error(err)
}

func (c *httpClient) UpdateOrgMember(name string, username string, in *api.UpdateOrgMemberRequest) (*api.OrgMember, error) {
	out := &api.OrgMember{}
	rawURL := fmt.Sprintf(pathOrgMember, c.base, name, username)
	err := c.post(rawURL, http.StatusOK, in, out)
	return out, errio.Error(err)
}

// RevokeOrgMember revokes an organization member.
func (c *httpClient) RevokeOrgMember(name string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
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
func (c *httpClient) get(rawURL string, out interface{}) error {
	err := c.do(rawURL, "GET", http.StatusOK, nil, out)
	return errio.Error(err)
}

// post is a helper function to make an http POST request
func (c *httpClient) post(rawURL string, expectedStatus int, in interface{}, out interface{}) error {
	err := c.do(rawURL, "POST", expectedStatus, in, out)
	return errio.Error(err)
}

// put is a helper function to make an http PUT request.
func (c *httpClient) put(rawURL string, expectedStatus int, in interface{}, out interface{}) error {
	err := c.do(rawURL, "PUT", expectedStatus, in, out)
	return errio.Error(err)
}

// patch is a helper function to make an http PATCH request.
func (c *httpClient) patch(rawURL string, expectedStatus int, in interface{}, out interface{}) error {
	err := c.do(rawURL, "PATCH", expectedStatus, in, out)
	return errio.Error(err)
}

// delete is a helper function to make an http DELETE request.
func (c *httpClient) delete(rawURL string, out interface{}) error {
	err := c.do(rawURL, "DELETE", http.StatusOK, nil, out)
	return errio.Error(err)
}

// Helper function to make an http request. Parses the url, encodes in as the request body,
// executes an http request. If the server returns the wrong statuscode, we try to parse
// the error and return it. If everything went well, it decodes the response body into out.
func (c *httpClient) do(rawURL string, method string, expectedStatus int, in interface{}, out interface{}) error {
	uri, err := url.Parse(rawURL)
	if err != nil {
		return errio.Error(err)
	}

	req, err := http.NewRequest(method, uri.String(), nil)
	if err != nil {
		return errio.Error(err)
	}

	err = httpio.EncodeRequest(req, in)
	if err != nil {
		return errio.Error(err)
	}

	err = c.credential.AddAuthentication(req)
	if err != nil {
		return errio.Error(err)
	}

	req.Header.Set("User-Agent", "SecretHub/"+c.version)

	resp, err := c.client.Do(req)
	if err != nil {
		return errio.Error(err)
	}

	if resp.StatusCode == http.StatusUpgradeRequired {
		return errClient.Code("out_of_date").Errorf(
			"Client is out of date\n" +
				"Go to `https://secrethub.io/docs/getting-started/install` to see how to update your client.")
	} else if resp.StatusCode != expectedStatus {
		log.Debugf("unexpected status code: %d (actual) != %d (expected)", resp.StatusCode, expectedStatus)
		return httpio.ParseError(resp)
	}

	err = httpio.DecodeResponse(resp, out)
	if err != nil {
		return errio.StatusError(err)
	}

	return nil
}
