package api

import (
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

const (
	AuthMethodAWSSTS = "aws-sts"

	SessionTypeHMAC = "hmac"
)

var (
	ErrInvalidSessionType  = errAPI.Code("invalid_session_type").Error("invalid session type provided for authentication request")
	ErrInvalidPayload      = errAPI.Code("invalid_payload").Error("invalid payload provided for authentication request")
	ErrIncorrectAuthMethod = errAPI.Code("incorrect_auth_method").ErrorPref("wrong auth method, expected %s")
	ErrMissingField        = errAPI.Code("missing_field").ErrorPref("request is missing field %s")
)

type AuthRequest struct {
	Method      *string `json:"method"`
	SessionType *string `json:"session_type"`
}

type AuthRequestAWSSTS struct {
	AuthRequest
	Payload *AuthPayloadAWSSTS `json:"payload"`
}

type AuthPayloadAWSSTS struct {
	Region  *string `json:"region"`
	Request *[]byte `json:"request"`
}

func (r AuthRequest) Validate() error {
	if r.SessionType == nil {
		return ErrMissingField("session_type")
	}
	if *r.SessionType != SessionTypeHMAC {
		return ErrInvalidSessionType
	}
}

func NewAuthRequestAWSSTS(sessionType, region string, stsRequest []byte) AuthRequestAWSSTS {
	return AuthRequestAWSSTS{
		AuthRequest: AuthRequest{
			Method:      String(AuthMethodAWSSTS),
			SessionType: &sessionType,
		},
		Payload: &AuthPayloadAWSSTS{
			Region:  &region,
			Request: &stsRequest,
		},
	}
}

func (r AuthRequestAWSSTS) Validate() error {
	if err := r.AuthRequest.Validate(); err != nil {
		return err
	}
	if r.Method == nil {
		return ErrMissingField("method")
	}
	if *r.Method != AuthMethodAWSSTS {
		return ErrIncorrectAuthMethod(AuthMethodAWSSTS)
	}
	if r.Payload == nil {
		return ErrMissingField("payload")
	}
	if err := r.Payload.Validate(); err != nil {
		return err
	}
	return nil
}

func (pl AuthPayloadAWSSTS) Validate() error {
	if pl.Region == nil {
		return ErrMissingField("region")
	}
	if pl.Request == nil {
		return ErrMissingField("request")
	}
	return nil
}

type AuthResponse struct {
	AccountID *uuid.UUID `json:"account_id"`
	Expires   *time.Time `json:"expires"`
	//Region    string    `json:"region"`
	SessionType *string `json:"session_type"`
}

type AuthResponseHMAC struct {
	AuthResponse
	Payload *SessionPayloadHMAC `json:"session_payload"`
}

type SessionPayloadHMAC struct {
	SessionID *uuid.UUID `json:"session_id"`
	SecretKey *string    `json:"secret_key"`
}

func (r AuthResponse) Validate() error {
	if r.AccountID == nil {
		return ErrMissingField("account_id")
	}
	if r.Expires == nil {
		return ErrMissingField("expires")
	}
	if r.SessionType == nil {
		return ErrMissingField("session_type")
	}
	if *r.SessionType != SessionTypeHMAC {
		return ErrInvalidSessionType
	}
	return nil
}

func (r AuthResponseHMAC) Validate() error {
	if err := r.AuthResponse.Validate(); err != nil {
		return err
	}
	if r.Payload == nil {
		return ErrMissingField("payload")
	}
	if err := r.Payload.Validate(); err != nil {
		return err
	}
	return nil
}

func (pl SessionPayloadHMAC) Validate() error {
	if pl.SessionID == nil {
		return ErrMissingField("session_id")
	}
	if pl.SecretKey == nil {
		return ErrMissingField("secret_key")
	}
	return nil
}
