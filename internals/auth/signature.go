package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"time"

	"fmt"

	"github.com/secrethub/secrethub-go/internals/errio"
)

const (
	// AuthHeaderVersionV1 is the authorization header tag used for authorization
	// headers that include the signing method.
	AuthHeaderVersionV1 = "SecretHub-v1"
)

// Errors
var (
	errNamespace                  = errio.Namespace("authentication")
	ErrCannotParseDateHeader      = errNamespace.Code("parse_date_header_failed").StatusError("could not authenticate request because the date header of the auth message could not be parsed", http.StatusBadRequest)
	ErrInvalidAuthorizationHeader = errNamespace.Code("invalid_authorization_header").StatusErrorf("could not authenticate request because the authorization header has invalid format", http.StatusBadRequest)
	ErrOutdatedSignatureProtocol  = errNamespace.Code("outdated_signature_protocol").StatusError("the signature protocol used for authentication is outdated, please upgrade to a newer version", http.StatusBadRequest)

	ErrMalformedSignature = errNamespace.Code("malformed_signature").StatusError("could not authenticate request because the signature is malformed", http.StatusBadRequest)
	ErrSignatureExpired   = errNamespace.Code("signature_expired").StatusError("could not authenticate request because signature has expired", http.StatusUnauthorized)
	ErrSignatureFuture    = errNamespace.Code("signature_future").StatusError("could not authenticate request because signature timestamp is too far in the future", http.StatusUnauthorized)
)

// Signer provides proof that given bytes are processed by the owner of the signer.
type Signer interface {
	ID() (string, error)
	Sign([]byte) ([]byte, error)
	SignMethod() string
}

// Authenticator proofs that an HTTP request is made by the owner of the authenticator.
type Authenticator interface {
	Authenticate(r *http.Request) error
}

type httpSigner struct {
	signer Signer
}

// NewHTTPSigner creates an authenticator that uses the given signer to prove the owner
// of the signer is making the  HTTP request.
func NewHTTPSigner(signer Signer) Authenticator {
	return httpSigner{
		signer: signer,
	}
}

// Authenticate signs the request and adds authentication information
// to the request in the `Authorization` HTTP Header. The HTTP Header contains
// the following information:
//
//	Authorization: 	SH1-<signing method> <authentication_identifier>:<signature>
//	Date: 			<current_utc_time_in_RFC1123>
//
// The Authorization Header is composed of the following elements:
// - The 'SH1' part identifies the authorization header format.
// - The <signing method> identifies the method used to produce the signature.
//   This is used server side to select the corresponding verification method.
// - The <authentication_identifier> uniquely identifies the signer used
//   to sign the request with. This identifier is used server side to verify
//   the <signature>.
// - The <signature> is a signed digest of selected elements of the request,
//   encoded as base64 with standard encoding. See getMessage for the elements
//   contained in the digest's signature.
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
func (s httpSigner) Authenticate(r *http.Request) error {
	formattedTime := time.Now().UTC().Format(time.RFC1123)
	r.Header.Set("Date", formattedTime)

	message, err := getMessage(r)
	if err != nil {
		return errio.Error(err)
	}

	signature, err := s.signer.Sign(message)
	if err != nil {
		return errio.Error(err)
	}

	base64EncodedSignature := base64.StdEncoding.EncodeToString(signature)

	id, err := s.signer.ID()
	if err != nil {
		return errio.Error(err)
	}

	r.Header.Set("Authorization",
		fmt.Sprintf("%s-%s %s:%s",
			AuthHeaderVersionV1,
			s.signer.SignMethod(),
			id,
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
