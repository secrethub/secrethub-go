package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

const (
	AuthMethodAWSSTS = "aws-sts"

	SessionTypeHMAC = "hmac"
)

var (
	ErrInvalidSessionType = errAPI.Code("invalid_session_type").StatusError("invalid session type provided for authentication request", http.StatusBadRequest)
	ErrInvalidPayload     = errAPI.Code("invalid_payload").StatusError("invalid payload provided for authentication request", http.StatusBadRequest)
	ErrInvalidAuthMethod  = errAPI.Code("invalid_auth_method").StatusError("invalid auth method", http.StatusBadRequest)
	ErrMissingField       = errAPI.Code("missing_field").StatusErrorPref("request is missing field %s", http.StatusBadRequest)
)

type AuthRequest struct {
	Method      *string     `json:"method"`
	SessionType *string     `json:"session_type"`
	Payload     interface{} `json:"payload"`
}

type AuthPayloadAWSSTS struct {
	Region  *string `json:"region"`
	Request *[]byte `json:"request"`
}

func NewAuthRequestAWSSTS(sessionType, region string, stsRequest []byte) AuthRequest {
	return AuthRequest{
		Method:      String(AuthMethodAWSSTS),
		SessionType: &sessionType,
		Payload: &AuthPayloadAWSSTS{
			Region:  &region,
			Request: &stsRequest,
		},
	}
}

func (r AuthRequest) UnmarshalJSON(b []byte) error {
	encodedPayload := json.RawMessage{}
	r.Payload = &encodedPayload
	err := json.Unmarshal(b, &r)
	if err != nil {
		return err
	}

	if r.Method == nil {
		return ErrInvalidAuthMethod
	}

	switch *r.Method {
	case AuthMethodAWSSTS:
		r.Payload = &AuthPayloadAWSSTS{}
	default:
		return ErrInvalidAuthMethod
	}

	err = json.Unmarshal(encodedPayload, r.Payload)
	if err != nil {
		return err
	}
	return nil
}

func (r AuthRequest) Validate() error {
	if r.SessionType == nil {
		return ErrMissingField("session_type")
	}
	if *r.SessionType != SessionTypeHMAC {
		return ErrInvalidSessionType
	}
	if r.Method == nil {
		return ErrMissingField("method")
	}
	switch *r.Method {
	case AuthMethodAWSSTS:
		authPayload, ok := r.Payload.(AuthPayloadAWSSTS)
		if !ok {
			return ErrInvalidPayload
		}
		if err := authPayload.Validate(); err != nil {
			return err
		}
	default:
		return ErrInvalidAuthMethod
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
