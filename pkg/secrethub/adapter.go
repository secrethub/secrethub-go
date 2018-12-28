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

// NewClient creates a new SecretHub client.
// It overrides the default configuration with the options when given.
func NewClient(credential Credential, opts *ClientOptions) (*ClientAdapter, error) {
	client, err := newClient(credential, opts)
	if err != nil {
		return nil, err
	}

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
	}, nil
}
