package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

const (
	AuthMethodAWSSTS = "aws-sts"

	SessionTypeHMAC SessionType = "hmac"
)

var (
	ErrInvalidSessionType = errAPI.Code("invalid_session_type").StatusError("invalid session type provided for authentication request", http.StatusBadRequest)
	ErrInvalidPayload     = errAPI.Code("invalid_payload").StatusError("invalid payload provided for authentication request", http.StatusBadRequest)
	ErrInvalidAuthMethod  = errAPI.Code("invalid_auth_method").StatusError("invalid auth method", http.StatusBadRequest)
	ErrMissingField       = errAPI.Code("missing_field").StatusErrorPref("request is missing field %s", http.StatusBadRequest)
	ErrSessionNotFound    = errAPI.Code("session_not_found").StatusError("session could not be found, it might have expired", http.StatusForbidden)
	ErrSessionExpired     = errAPI.Code("session_expired").StatusError("session has expired", http.StatusForbidden)
)

type SessionType string

type AuthRequest struct {
	Method      *string      `json:"method"`
	SessionType *SessionType `json:"session_type"`
	Payload     interface{}  `json:"payload"`
}

type AuthPayloadAWSSTS struct {
	Region  *string `json:"region"`
	Request *[]byte `json:"request"`
}

func NewAuthRequestAWSSTS(sessionType SessionType, region string, stsRequest []byte) AuthRequest {
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

type Session struct {
	SessionID  *uuid.UUID   `json:"session_id"`
	Expiration *time.Time   `json:"expiration"`
	Type       *SessionType `json:"type"`
	Payload    interface{}  `json:"payload"`
}

type SessionPayloadHMAC struct {
	SecretKey *string `json:"secret_key"`
}

func (s Session) UnmarshalJSON(b []byte) error {
	encodedPayload := json.RawMessage{}
	s.Payload = &encodedPayload
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	if s.Type == nil {
		return ErrInvalidSessionType
	}

	switch *s.Type {
	case SessionTypeHMAC:
		s.Payload = &SessionPayloadHMAC{}
	default:
		return ErrInvalidSessionType
	}

	err = json.Unmarshal(encodedPayload, s.Payload)
	if err != nil {
		return err
	}
	return nil
}

func (s Session) Validate() error {
	if s.SessionID == nil {
		return ErrMissingField("session_id")
	}
	if s.Expiration == nil {
		return ErrMissingField("expiration")
	}
	if s.Type == nil {
		return ErrMissingField("type")
	}
	if *s.Type != SessionTypeHMAC {
		return ErrInvalidSessionType
	}
	if s.Payload == nil {
		return ErrMissingField("payload")
	}
	return nil
}

func (pl SessionPayloadHMAC) Validate() error {
	if pl.SecretKey == nil {
		return ErrMissingField("secret_key")
	}
	return nil
}
