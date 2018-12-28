package secrethub

// ClientAdapter will become the Client type later.
// TODO SHDEV-1027: Move the client implementations to the services and rename this struct to client.
type ClientAdapter struct {
	AccessRules AccessRuleService
	Accounts    AccountService
	Dirs        DirService
	Orgs        OrgService
	Repos       RepoService
	Secrets     SecretService
	Services    ServiceService
	Users       UserService
}

// NewClientAdapter will become NewClient later.
// TODO SHDEV-1027: Rename to NewClient and move the client implementations directly to the services.
// The client argument can then be removed.
func NewClientAdapter(client *client) *ClientAdapter {
	return &ClientAdapter{
		AccessRules: &accessRuleService{
			client: client,
		},
		Accounts: &accountService{
			client: client,
		},
		Dirs: &dirService{
			client: client,
		},
		Orgs: &orgService{
			client: client,
		},
		Repos: &repoService{
			client: client,
		},
		Secrets: &secretService{
			client: client,
		},
		Services: &serviceService{
			client: client,
		},
		Users: &userService{
			client: client,
		},
	}
}
