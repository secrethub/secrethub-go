package api

import (
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"
)

// RevokeResponse is returned when a revoke command is executed.
type RevokeResponse struct {
	RevokedSecretVersions []*EncryptedSecretVersion `json:"revoked_secret_versions"`
	RevokedSecretKeys     []*SecretKey              `json:"revoked_secret_keys"`
}

// RevokeOrgResponse is returned as the effect of revoking an account from a repository.
type RevokeOrgResponse struct {
	DryRun       bool                  `json:"dry"` // Dry indicates whether it was a dry run or not.
	Repos        []*RevokeRepoResponse `json:"repos"`
	StatusCounts map[string]int        `json:"status_counts"` // StatusCounts contains aggregate counts of the repos the account is revoked from.
}

// RevokeRepoResponse is returned as the effect of revoking an account from a repo.
type RevokeRepoResponse struct {
	Namespace                 string `json:"namespace"` // Added for display purposes
	Name                      string `json:"name"`      // Added for display purposes
	Status                    string `json:"status"`
	RevokedSecretVersionCount int    `json:"revoked_secret_version_count"`
	RevokedSecretKeyCount     int    `json:"revoked_secret_key_count"`
}

// RevokeOpts contains optional query parameters for revoke requests.
type RevokeOpts struct {
	DryRun bool `url:"dry_run"` // Dry performs a dry run without actually revoking the account.
}

// Unmarshal decodes url.Values into the options struct,
// setting default values if not present in the query values.
// TODO SHDEV-817: refactor this to a more extendable mechanism.
func (o *RevokeOpts) Unmarshal(values url.Values) {
	dry := values.Get("dry_run")
	if strings.ToLower(dry) == "true" {
		o.DryRun = true
	} else {
		o.DryRun = false
	}
}

// Values returns the url.Values encoding of the options.
func (o RevokeOpts) Values() (url.Values, error) {
	return query.Values(o)
}
