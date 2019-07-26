package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// AuthMethod options
const (
	AuthMethodAWSSTS = "aws-sts"
)

// SessionType options
const (
	SessionTypeHMAC SessionType = "hmac"
)

// Errors
var (
	ErrInvalidSessionType    = errAPI.Code("invalid_session_type").StatusError("invalid session type provided for authentication request", http.StatusBadRequest)
	ErrInvalidPayload        = errAPI.Code("invalid_payload").StatusError("invalid payload provided for authentication request", http.StatusBadRequest)
	ErrInvalidAuthMethod     = errAPI.Code("invalid_auth_method").StatusError("invalid auth method", http.StatusBadRequest)
	ErrMissingField          = errAPI.Code("missing_field").StatusErrorPref("request is missing field %s", http.StatusBadRequest)
	ErrSessionNotFound       = errAPI.Code("session_not_found").StatusError("session could not be found, it might have expired", http.StatusForbidden)
	ErrSessionExpired        = errAPI.Code("session_expired").StatusError("session has expired", http.StatusForbidden)
	ErrAuthFailed            = errAPI.Code("auth_failed").StatusError("authentication failed", http.StatusForbidden)
	ErrCouldNotGetEndpoint   = errAPI.Code("wrong_endpoint").StatusError("could not find an AWS endpoint for the provided region", http.StatusBadRequest)
	ErrAWSException          = errAPI.Code("aws_exception").StatusError("encountered an unexpected problem while verifying your identity on AWS. Please try again later.", http.StatusFailedDependency)
	ErrNoServiceWithRole     = errAPI.Code("no_service_with_role").StatusErrorPref("no service account found that is linked to the IAM role '%s'", http.StatusNotFound)
	ErrNoAWSCredentials      = errAPI.Code("missing_aws_credentials").StatusError("request was not signed with AWS credentials", http.StatusUnauthorized)
	ErrInvalidAWSCredentials = errAPI.Code("invalid_aws_credentials").StatusError("credentials were not accepted by AWS", http.StatusUnauthorized)
)

// SessionType defines how a session can be used.
type SessionType string

// AuthRequest is a request to authenticate and request a session.
type AuthRequest struct {
	Method      *string      `json:"method"`
	SessionType *SessionType `json:"session_type"`
	Payload     interface{}  `json:"payload"`
}

// AuthPayloadAWSSTS is the authentication payload used for authenticating with AWS STS.
type AuthPayloadAWSSTS struct {
	Region  *string `json:"region"`
	Request []byte  `json:"request"`
}

// NewAuthRequestAWSSTS returns a new AuthRequest for authentication using AWS STS.
func NewAuthRequestAWSSTS(sessionType SessionType, region string, stsRequest []byte) AuthRequest {
	return AuthRequest{
		Method:      String(AuthMethodAWSSTS),
		SessionType: &sessionType,
		Payload: &AuthPayloadAWSSTS{
			Region:  &region,
			Request: stsRequest,
		},
	}
}

// UnmarshalJSON converts a JSON representation into a AuthRequest with the correct Payload.
func (r *AuthRequest) UnmarshalJSON(b []byte) error {
	// Declare a private type to avoid recursion into this function.
	type authRequest AuthRequest

	var rawMessage json.RawMessage
	dec := authRequest{
		Payload: &rawMessage,
	}

	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}

	if dec.Method == nil {
		return ErrInvalidAuthMethod
	}

	switch *dec.Method {
	case AuthMethodAWSSTS:
		dec.Payload = &AuthPayloadAWSSTS{}
	default:
		return ErrInvalidAuthMethod
	}

	if rawMessage != nil {
		err = json.Unmarshal(rawMessage, dec.Payload)
		if err != nil {
			return err
		}
	}
	*r = AuthRequest(dec)
	return nil
}

// Validate whether an AuthRequest is a valid request.
func (r *AuthRequest) Validate() error {
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
		authPayload, ok := r.Payload.(*AuthPayloadAWSSTS)
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

// Validate whether the AuthPayloadAWSSTS is valid.
func (pl AuthPayloadAWSSTS) Validate() error {
	if pl.Region == nil {
		return ErrMissingField("region")
	}
	if pl.Request == nil {
		return ErrMissingField("request")
	}
	return nil
}

// NewSessionHMAC returns a HMAC type api.Session.
func NewSessionHMAC(sessionID uuid.UUID, expiration time.Time, secretKey string) *Session {
	t := SessionTypeHMAC
	return &Session{
		SessionID: &sessionID,
		Expires:   &expiration,
		Type:      &t,
		Payload: &SessionPayloadHMAC{
			SecretKey: &secretKey,
		},
	}
}

// Session represents a session that can be used for authentication to the server.
type Session struct {
	SessionID *uuid.UUID   `json:"session_id"`
	Expires   *time.Time   `json:"expires"`
	Type      *SessionType `json:"type"`
	Payload   interface{}  `json:"payload"`
}

// SessionPayloadHMAC is the payload of a HMAC typed session.
type SessionPayloadHMAC struct {
	SecretKey *string `json:"secret_key"`
}

// SessionHMAC is a session that uses the HMAC algorithm to verify the authentication.
type SessionHMAC struct {
	SessionID  uuid.UUID
	Expiration time.Time
	Payload    SessionPayloadHMAC
}

// UnmarshalJSON converts a JSON representation into a Session with the correct Payload.
func (s *Session) UnmarshalJSON(b []byte) error {
	// Declare a private type to avoid recursion into this function.
	type session Session

	var rawMessage json.RawMessage
	dec := session{
		Payload: &rawMessage,
	}

	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}

	if dec.Type == nil {
		return ErrInvalidSessionType
	}

	switch *dec.Type {
	case SessionTypeHMAC:
		dec.Payload = &SessionPayloadHMAC{}
	default:
		return ErrInvalidSessionType
	}

	if rawMessage != nil {
		err = json.Unmarshal(rawMessage, dec.Payload)
		if err != nil {
			return err
		}
	}
	*s = Session(dec)
	return nil
}

type validator interface {
	Validate() error
}

// Validate whether the Session is valid.
func (s *Session) Validate() error {
	if s.SessionID == nil {
		return ErrMissingField("session_id")
	}
	if s.Expires == nil {
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
	payload := s.Payload.(validator)
	if err := payload.Validate(); err != nil {
		return err
	}
	return nil
}

// HMAC returns the HMAC specific representation of this session.
func (s *Session) HMAC() *SessionHMAC {
	payload := s.Payload.(*SessionPayloadHMAC)
	return &SessionHMAC{
		SessionID:  *s.SessionID,
		Expiration: *s.Expires,
		Payload:    *payload,
	}
}

// Validate whether the SessionPayloadHMAC is valid.
func (pl *SessionPayloadHMAC) Validate() error {
	if pl.SecretKey == nil {
		return ErrMissingField("secret_key")
	}
	return nil
}
