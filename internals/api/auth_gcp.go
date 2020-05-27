package api

// AuthPayloadGCPServiceAccount is the authentication payload used for authenticating with a GCP Service Account.
type AuthPayloadGCPServiceAccount struct {
	IDToken string `json:"id_token"`
}

// NewAuthRequestGCPServiceAccount returns a new AuthRequest for authentication using a GCP Service Account.
func NewAuthRequestGCPServiceAccount(sessionType SessionType, idToken string) AuthRequest {
	return AuthRequest{
		Method:      AuthMethodGCPServiceAccount,
		SessionType: sessionType,
		Payload: &AuthPayloadGCPServiceAccount{
			IDToken: idToken,
		},
	}
}

func (pl AuthPayloadGCPServiceAccount) Validate() error {
	if pl.IDToken == "" {
		return ErrMissingField("id_token")
	}
	return nil
}
