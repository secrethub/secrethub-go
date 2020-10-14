// Package secrethub provides the SecretHub API client,
// look here to read, write and manage secrets.
package secrethub

import (
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/docker/docker/pkg/parsers/operatingsystem"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/configdir"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

var (
	userAgentPrefix = "SecretHub/1.0 secrethub-go/" + strings.TrimPrefix(ClientVersion, "v")
)

// Errors
var (
	ErrUnknownIdentityProvider = errClient.Code("unknown_identity_provider").ErrorPref("%s is not a supported identity provider. Valid options are `aws` and `key`.")
)

// ClientInterface is an interface that can be used to consume the SecretHub client and is implemented by secrethub.Client.
type ClientInterface interface {
	// AccessRules returns a service used to manage access rules.
	AccessRules() AccessRuleService
	// Accounts returns a service used to manage SecretHub accounts.
	Accounts() AccountService
	// Credentials returns a service used to manage credentials.
	Credentials() CredentialService
	// Dirs returns a service used to manage directories.
	Dirs() DirService
	// IDPLinks returns a service used to manage links between namespaces and Identity Providers.
	IDPLinks() IDPLinkService
	// Me returns a service used to manage the current authenticated account.
	Me() MeService
	// Orgs returns a service used to manage shared organization workspaces.
	Orgs() OrgService
	// Repos returns a service used to manage repositories.
	Repos() RepoService
	// Secrets returns a service used to manage secrets.
	Secrets() SecretService
	// Services returns a service used to manage non-human service accounts.
	Services() ServiceService
	// Users returns a service used to manage (human) user accounts.
	Users() UserService
}

var (
	errClient = errio.Namespace("client")

	whitelistAppInfoName = regexp.MustCompile("^[a-zA-Z0-9_-]{2,50}$")
)

// Errors
var (
	ErrInvalidAppInfoName = errClient.Code("invalid_app_info_name").Error("name must be 2-50 characters long, only alphanumeric, underscore (_), and dash (-)")
)

// Client is a client for the SecretHub HTTP API.
type Client struct {
	httpClient *http.Client

	decrypter credentials.Decrypter

	// account is the api.Account for this SecretHub account.
	// Do not use this field directly, but use client.getMyAccount() instead.
	account *api.Account

	// accountKey is the intermediate key for this SecretHub account.
	// Do not use this field directly, but use client.getAccountKey() instead.
	accountKey *crypto.RSAPrivateKey

	// repoindexKeys are the keys used to generate blind names in the repo.
	// These are cached
	repoIndexKeys map[api.RepoPath]*crypto.SymmetricKey

	appInfo   []*AppInfo
	ConfigDir *configdir.Dir
}

// AppInfo contains information about the application that is using the SecretHub client.
// It is used to identify the application to the SecretHub API.
type AppInfo struct {
	Name    string
	Version string
}

func (i AppInfo) userAgentComponent() string {
	res := i.Name
	if i.Version != "" {
		res += "/" + strings.TrimPrefix(i.Version, "v")
	}
	return res
}

// ValidateName returns an error if the provided app name is not set or doesn't match alphanumeric, underscore (_), and dash (-) characters, or length of 2-50 characters.
func (i AppInfo) ValidateName() error {
	if i.Name == "" || !whitelistAppInfoName.MatchString(i.Name) {
		return ErrInvalidAppInfoName
	}

	return nil
}

// NewClient creates a new SecretHub client. Provided options are applied to the client.
//
// If no WithCredentials() option is provided, the client tries to find a key credential at the following locations (in order):
//   1. The SECRETHUB_CREDENTIAL environment variable.
//   2. The credential file placed in the directory given by the SECRETHUB_CONFIG_DIR environment variable.
//   3. The credential file found in <user's home directory>/.secrethub/credential.
// If no key credential could be found, a Client is returned that can only be used for unauthenticated routes.
func NewClient(with ...ClientOption) (*Client, error) {
	client := &Client{
		httpClient:    http.NewClient(),
		repoIndexKeys: make(map[api.RepoPath]*crypto.SymmetricKey),
		appInfo:       []*AppInfo{},
	}
	err := client.with(with...)
	if err != nil {
		return nil, err
	}

	// ConfigDir should be fully initialized before loading any default credentials.
	if client.ConfigDir == nil {
		configDir, err := configdir.Default()
		if err != nil {
			return nil, err
		}
		client.ConfigDir = configDir
	}

	// Try to use default key credentials if none provided explicitly
	if !client.httpClient.IsAuthenticated() && client.decrypter == nil {
		identityProvider := os.Getenv("SECRETHUB_IDENTITY_PROVIDER")

		var provider credentials.Provider
		switch strings.ToLower(identityProvider) {
		case "", "key":
			provider = credentials.UseKey(client.DefaultCredential())
		case "aws":
			provider = credentials.UseAWS()
		case "gcp":
			provider = credentials.UseGCPServiceAccount()
		default:
			return nil, ErrUnknownIdentityProvider(identityProvider)
		}

		err := client.with(WithCredentials(provider))
		// nolint: staticcheck
		if err != configdir.ErrCredentialNotFound {
			return nil, err
		} else if err != nil {
			// TODO: log that default credential was not found.
			// Do go on because we want to allow an unauthenticated client.
		}
	}

	appName := os.Getenv("SECRETHUB_APP_INFO_NAME")
	if appName != "" {
		appVersion := os.Getenv("SECRETHUB_APP_INFO_VERSION")
		topLevelAppInfo := &AppInfo{
			Name:    appName,
			Version: appVersion,
		}
		// Ignore app info from environment variable if name is invalid
		if err = topLevelAppInfo.ValidateName(); err == nil {
			client.appInfo = append(client.appInfo, topLevelAppInfo)
		}
	}

	userAgent := client.userAgent()

	client.httpClient.Options(http.WithUserAgent(userAgent))

	return client, nil
}

// Must is a helper function to ensure the Client is valid and there was no
// error when calling a NewClient function.
//
// This helper is intended to be used in initialization to load the
// Session and configuration at startup. For example:
//
//     var client = secrethub.Must(secrethub.NewClient())
func Must(c *Client, err error) *Client {
	if err != nil {
		panic(err)
	}
	return c
}

// AccessRules returns a service used to manage access rules.
func (c *Client) AccessRules() AccessRuleService {
	return newAccessRuleService(c)
}

// Accounts returns a service used to manage SecretHub accounts.
func (c *Client) Accounts() AccountService {
	return newAccountService(c)
}

// Credentials returns a service used to manage credentials.
func (c *Client) Credentials() CredentialService {
	return newCredentialService(c, c.httpClient.IsAuthenticated, c.isKeyed)
}

// Dirs returns a service used to manage directories.
func (c *Client) Dirs() DirService {
	return newDirService(c)
}

func (c *Client) IDPLinks() IDPLinkService {
	return newIDPLinkService(c)
}

// Me returns a service used to manage the current authenticated account.
func (c *Client) Me() MeService {
	return newMeService(c)
}

// Orgs returns a service used to manage shared organization workspaces.
func (c *Client) Orgs() OrgService {
	return newOrgService(c)
}

// Repos returns a service used to manage repositories.
func (c *Client) Repos() RepoService {
	return newRepoService(c)
}

// Secrets returns a service used to manage secrets.
func (c *Client) Secrets() SecretService {
	return newSecretService(c)
}

// Services returns a service used to manage non-human service accounts.
func (c *Client) Services() ServiceService {
	return newServiceService(c)
}

// Users returns a service used to manage (human) user accounts.
func (c *Client) Users() UserService {
	return newUserService(c)
}

// with applies ClientOptions to a Client. Should only be called during initialization.
func (c *Client) with(options ...ClientOption) error {
	for _, o := range options {
		err := o(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// DefaultCredential returns a reader pointing to the configured credential,
// sourcing it either from the SECRETHUB_CREDENTIAL environment variable or
// from the configuration directory.
func (c *Client) DefaultCredential() credentials.Reader {
	envCredential := os.Getenv("SECRETHUB_CREDENTIAL")
	if envCredential != "" {
		return credentials.FromString(envCredential)
	}

	return c.ConfigDir.Credential()
}

func (c *Client) isKeyed() bool {
	return c.decrypter != nil
}

func (c *Client) userAgent() string {
	userAgent := userAgentPrefix
	for _, info := range c.appInfo {
		userAgent += " " + info.userAgentComponent()
	}
	osName, err := operatingsystem.GetOperatingSystem()
	if err != nil {
		osName = strings.Title(runtime.GOOS)
	}
	osName = strings.TrimSpace(osName) // GetOperatingSystem may read from a cmd output without trimming whitespace
	userAgent += " (" + osName + "; " + runtime.GOARCH + ")"

	return userAgent
}
