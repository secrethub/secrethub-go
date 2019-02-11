package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/keylockerbv/secrethub-go/pkg/api"

	"fmt"

	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

const (
	// maxLifetime is the maximum lifetime of a valid signature.
	maxLifetime time.Duration = 1 * time.Minute

	// maxClockSkew is the maximum time we allow a client's clock to be
	// out of sync with the server clock. The speed of clients and the
	// timeout values for clients mean the clock skew should also take
	// into account the time it may take for a request to be accepted
	// by the server.
	//
	// For reference, we include these two articles on the max clock skew AWS:
	// - 2017, states AWS maxClockSkew is 5 min: http://altereos.com/2017/02/how-to-correct-clock-skew-in-aws/
	// - 2015, suggests AWS maxClockSkew is 15 min: https://aws.amazon.com/blogs/developer/clock-skew-correction/
	maxClockSkew time.Duration = 5 * time.Minute

	// maxExpirationDifference is the maximum time difference between a
	// request's signature and the current time to be considered valid.
	maxExpirationDifference = maxLifetime + maxClockSkew

	// MethodTagSignatureV1 defines the deprecated v1 Authorization header tag.
	MethodTagSignatureV1 = "SecretHub"
	// MethodTagSignatureV2 defines the deprecated v2 Authorization header tag.
	MethodTagSignatureV2 = "SecretHub-Sig2"
	// MethodTagSignature defines the method's Authorization header tag.
	MethodTagSignature = "secrethub-sig-v1"
)

// Errors
var (
	errNamespace                  = errio.Namespace("authentication")
	ErrBadRequest                 = errNamespace.Code("bad_request").StatusError("bad request", http.StatusBadRequest)
	ErrCannotParseDateHeader      = errNamespace.Code("parse_date_header_failed").StatusError("could not authenticate request because the date header of the auth message could not be parsed", http.StatusBadRequest)
	ErrInvalidAuthorizationHeader = errNamespace.Code("invalid_authorization_header").StatusErrorf("could not authenticate request because the authorization header must have format: %s identifier:base64_encoded_signature", http.StatusBadRequest, MethodTagSignature)
	ErrOutdatedSignatureProtocol  = errNamespace.Code("outdated_signature_protocol").StatusError("the signature protocol used for authentication is outdated, please upgrade to a newer version", http.StatusBadRequest)

	ErrMalformedSignature = errNamespace.Code("malformed_signature").StatusError("could not authenticate request because the signature is malformed", http.StatusBadRequest)
	ErrSignatureExpired   = errNamespace.Code("signature_expired").StatusError("could not authenticate request because signature has expired", http.StatusUnauthorized)
	ErrSignatureFuture    = errNamespace.Code("signature_future").StatusError("could not authenticate request because signature timestamp is too far in the future", http.StatusUnauthorized)
)

// CredentialSignature contains all necessary credentials to sign a request.
type CredentialSignature struct {
	key *crypto.RSAKey
}

// NewCredentialSignature initializes a new signing credentials struct.
func NewCredentialSignature(key *crypto.RSAKey) Credential {
	return CredentialSignature{
		key: key,
	}
}

// AddAuthentication signs the request and adds authentication information
// to the request in the `Authorization` HTTP Header. The HTTP Header contains
// the following information:
//
//	Authorization: 	SecretHub <authentication_identifier>:<signature>
//	Date: 			<current_utc_time_in_RFC1123>
//
// The Authorization Header is composed of the following elements:
// - The 'SecretHub' part identifies the authentication method used as this
// SecretHub method.
// - The <authentication_identifier> uniquely identifies the public key used
// to sign the request with. This public key is used server side to verify
// the <signature>.
// - The <signature> is a signed digest of selected elements of the request,
// encoded as base64 with standard encoding. See getMessage for the elements
// contained in the digest's signature.
//
// The Date header is set to the current time of the client making the request
// in the UTC timezone and using the RFC1123 format, as specified in the HTTP
// Header RFC. The Date header's value is also included in the digest and signed.
//
// The signature is only placed on generated and hashed data by the client.
// This eliminates the risk of placing a signature on data provided by a
// malicious attacker that is actually an encrypted piece of data. 'Tricking'
// a client into signing data supplied by the attacker would effectively
// decrypt it, which is a common risk of using the same key for both signing
// and decrypting.
//
// The signature could be reused by a Man-in-The-Middle attack. We mitigate
// this risk by using TLS, which encrypts HTTP Headers as well. This makes
// a MitM attack impossible without an attacker having access to the server's
// private TLS key. This solution is also proposed in RFC 4521 Section-4.1.
func (c CredentialSignature) AddAuthentication(r *http.Request) error {
	formattedTime := time.Now().UTC().Format(time.RFC1123)
	r.Header.Set("Date", formattedTime)

	message, err := getMessage(r)
	if err != nil {
		return errio.Error(err)
	}

	signature, err := c.key.Sign(message[:])
	if err != nil {
		return errio.Error(err)
	}

	base64EncodedSignature := base64.StdEncoding.EncodeToString(signature)

	identifier, err := c.key.GetIdentifier()
	if err != nil {
		return errio.Error(err)
	}

	r.Header.Set("Authorization",
		fmt.Sprintf("%s %s:%s",
			MethodTagSignature,
			identifier,
			base64EncodedSignature))

	return nil
}

// getMessage returns a message that uniquely identifies
// the HTTP request in the following format:
//
// <method>\n
// <content-hash>\n
// <date>\n
// <resource>;
//
// - The <method> part is the HTTP method used for the request.
// - The <content-hash> part is a SHA256 hash of the request body,
// encoded as base64 in standard encoding and with padding.
// - The <date> part is the date timestamp of the request and is
// retrieved from the HTTP Date header, formatted to RFC1123. Note
// that the Date header must have been set before calling the
// getMessage function.
// - The <resource> part identifies the requested REST resource by
// its url.
//
// An example of a POST request with a body:
//
// POST
// ot0Wva2htmGhHdCN7wRhZV//fbvXDC2Zihq3dllA/yA=
// Fri, 10 Mar 2017 16:25:54 CET
// /repos/jdoe/catpictures;
//
// An example of a GET request (without a body):
//
// GET
//
// Fri, 10 Mar 2017 16:25:55 CET
// /repos/jdoe/catpictures;
//
// This format shows the intent of the owner in the message at a given time:
// > A GET request on route /repos/jdoe/catpictures/ at Fri, 10 Mar 2017 16:25:54 CET
//
// This format is similar to the signature in RFC4251 and RFC4252,
// that specify the authentication used in the SSH protocol, and is
// similar to the format used by AWS for authenticating REST calls.
func getMessage(r *http.Request) ([]byte, error) {
	var result bytes.Buffer
	// Method \n
	result.WriteString(fmt.Sprintf("%s\n", r.Method))
	// Content-Hash
	if r.ContentLength == 0 {
		// Empty body
		result.WriteString("\n")
	} else {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, errio.Error(err)
		}

		// Restore the body to its original state so that it can be read again.
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		sum := sha256.Sum256(body)
		encoded := base64.StdEncoding.EncodeToString(sum[:])

		result.WriteString(fmt.Sprintf("%s\n", encoded))
	}
	// Date \n
	requestTime, err := time.Parse(time.RFC1123, r.Header.Get("Date"))
	if err != nil {
		return nil, ErrCannotParseDateHeader
	}
	result.WriteString(fmt.Sprintf("%s\n", requestTime))
	// Resource \n
	result.WriteString(fmt.Sprintf("%s;", r.URL.Path))

	return result.Bytes(), nil
}

// MethodSignature can authenticate signed HTTP request.
type MethodSignature struct {
	methodSignatureCommon
}

// credentialGetter can be used to retrieve credentials.
type credentialGetter interface {
	// GetCredential retrieves a credential.
	GetCredential(fingerprint string) (*api.Credential, error)
}

// NewMethodSignature returns a new MethodSignature.
func NewMethodSignature(credentialGetter credentialGetter) Method {
	return &MethodSignature{
		methodSignatureCommon{
			credentialGetter: credentialGetter,
			tag:              MethodTagSignature,
		},
	}
}

// methodSignatureCommon is a shared type that encodes
// signing logic for authentication.
type methodSignatureCommon struct {
	credentialGetter credentialGetter
	tag              tag
}

// Tag returns the Authorization format tag.
func (m methodSignatureCommon) Tag() string {
	return string(m.tag)
}

// Verify authenticates an account from an http request.
func (m methodSignatureCommon) Verify(r *http.Request) (*Result, error) {
	requestTime, err := time.Parse(time.RFC1123, r.Header.Get("Date"))
	if err != nil {
		return nil, ErrCannotParseDateHeader
	}

	err = isTimeValid(requestTime, time.Now().UTC())
	if err != nil {
		return nil, errio.Error(err)
	}

	format := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(format) != 2 || format[0] != m.Tag() {
		if format[0] == MethodTagSignatureV1 || format[0] == MethodTagSignatureV2 {
			return nil, ErrOutdatedSignatureProtocol
		}
		return nil, ErrInvalidAuthorizationHeader
	}

	identifier, encodedSignature, err := m.tag.parse(format[1])
	if err != nil {
		return nil, errio.StatusError(err)
	}

	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nil, ErrMalformedSignature
	}

	message, err := getMessage(r)
	if err != nil {
		return nil, errio.StatusError(err)
	}

	accountKey, err := m.credentialGetter.GetCredential(identifier)
	if err == api.ErrCredentialNotFound {
		// Note that this specific error check here smells pretty bad and
		// is the result of how the auth package is composed. We aim for
		// a loose coupling with the model/sql package, but here and at the
		// getCredential function the tight coupling is exposed. When possible,
		// let's freshen this stinky thing up.
		return nil, api.ErrSignatureNotVerified
	} else if err != nil {
		return nil, errio.StatusError(err)
	}

	err = crypto.Verify(accountKey.Verifier, message, signature)
	if err != nil {
		return nil, api.ErrSignatureNotVerified
	}

	return &Result{
		AccountID:   accountKey.AccountID,
		Fingerprint: accountKey.Fingerprint,
	}, nil
}

// tag is a helper type for dealing with two very similar formats,
// without introducing too much code duplication.
type tag string

// parse parses a formatted string that has been retrieved form the Authorization header,
// returning the identifier and signature.
func (t tag) parse(format string) (string, string, error) {
	parts := strings.Split(format, ":")

	if string(t) == MethodTagSignature && len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	return "", "", ErrInvalidAuthorizationHeader
}

// isTimeValid checks whether the time used for a request is valid, based on the server time.
// The window for a valid requestTime is defined as [serverTime-maxExpirationDifference; serverTime+maxClockSkew]
func isTimeValid(requestTime, serverTime time.Time) error {
	timeDiff := requestTime.Sub(serverTime)

	if timeDiff < -maxExpirationDifference {
		return ErrSignatureExpired
	}

	if timeDiff > maxClockSkew {
		return ErrSignatureFuture
	}

	return nil
}
