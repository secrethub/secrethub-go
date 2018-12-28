package secrethub

// Client is the SecretHub client.
type Client struct {
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
func NewClient(credential Credential, opts *ClientOptions) (*Client, error) {
	client, err := newClient(credential, opts)
	if err != nil {
		return nil, err
	}

	return &Client{
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
