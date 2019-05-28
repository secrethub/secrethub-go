package secrethub

type AuthMethodService interface {
	Authenticate() error
}

// AccountService handles authentication to the SercretHub API.
type AuthService interface {
	AWS() AuthMethodService
}

func newAuthService(client client) AuthService {
	return &authService{
		client: client,
	}
}

type authService struct {
	client client
}

// Members returns an OrgMemberService.
func (s authService) AWS() AuthMethodService {
	return newAWSAuthService(s.client)
}
