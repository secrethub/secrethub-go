package crypto

import (
	"crypto/rand"

	"github.com/keylockerbv/secrethub/core/errio"
)

const (
	// DefaultSaltLength defines the recommended length of salts used in
	// key derivation algorithms. The minimum value recommended by Section
	// 4.1 of  RFC 2898, Password-Based Cryptography (September 2000), is
	// 8 octets (64-bits).
	//
	// As recommended by the RFC, two non-random octets (16 bits) are prepended
	// to the salt. These 16 bits define the 'salt purpose' and are used to
	// distinguish between between different algorithms (e.g. AES-GCM), key
	// lengths (e.g. 256 bits) and operation types (e.g. credential encryption).
	// This distinction ensures salts are never reused for different purposes.
	// So, whenever a salt or it's derived value is used, the salt's
	// purpose should be verified.
	//
	// Because salt length does not significantly impact performance, we have
	// chosen the salt length to be very long. With 32 octet (256 bits) long
	// salts, we don't have to worry about world-wide uniqueness and collisions
	// are only likely to occur after generating 2^128 salts according to the
	// Birthday Paradox.
	//
	// Summarizing the RFC, choosing a sufficiently large salt length has
	// the following two benefits:
	//
	// 1. 	It is difficult for an opponent to precompute all the keys
	//		corresponding to a dictionary of passwords, or even the most
	//		likely keys. An opponent is thus limited to searching for
	//		passwords after a password-based operation has been performed
	//		and the salt is known.
	//
	// 2.	It is unlikely that the same key will be selected twice. This
	//      addresses some of the concerns about interactions between
	//      multiple uses of the same key, which may apply for some
	//      encryption and authentication techniques.
	//
	// Read more about this in the RFC itself: https://www.ietf.org/rfc/rfc2898.txt
	DefaultSaltLength = 32

	// MinSaltLength defines the minimal salt length as 8 random octets.
	// See DefaultSaltLength for a more extensive explanation.
	MinSaltLength = 8

	// saltPurposeByteLen defines the length of the byte representation of a salt
	// purpose. It is defined here to avoid magic numbers.
	saltPurposeByteLen = 2
)

// Errors
var (
	ErrInvalidSalt          = errCrypto.Code("invalid_salt").Error("salt must contain 2 purpose bytes and at least 8 bytes (64 bits) random bits")
	ErrInvalidSaltPurpose   = errCrypto.Code("invalid_salt_purpose").Error("salt purpose is invalid")
	ErrInvalidSaltOperation = errCrypto.Code("invalid_salt_operation").Error("salt operation type is invalid")
	ErrInvalidSaltAlgo      = errCrypto.Code("invalid_salt_algo").Error("salt algorithm is invalid")
)

// Salt defines a cryptographic salt to be used for key derivation functions,
// encryption schemes or message authentication schemes.
type Salt []byte

// Validate validates a salt.
func (s Salt) Validate() error {
	if len(s) < MinSaltLength+saltPurposeByteLen {
		return ErrInvalidSalt
	}

	return s.Purpose().Validate()
}

// Purpose returns a salt's purpose octect.
func (s Salt) Purpose() SaltPurpose {
	if len(s) > saltPurposeByteLen {
		return newSaltPurpose(SaltAlgo(s[0]), SaltOperation(s[1]))
	}
	return newSaltPurpose(SaltAlgoNone, SaltOperationNone)
}

// generateSalt generates a random salt of the given length and prepends
// the purpose to it, returning a salt with size 1+length.
//
// Note: this function has been made private on purpose as you should
// never generate your own salts outside this package and only use
// the public functions provided by the package.
func generateSalt(length int, algo SaltAlgo, operation SaltOperation) (Salt, error) {
	if length < MinSaltLength {
		return nil, ErrInvalidSalt
	}

	purpose := newSaltPurpose(algo, operation)
	err := purpose.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	randBytes := make([]byte, length)
	_, err = rand.Reader.Read(randBytes)
	if err != nil {
		return nil, errio.Error(err)
	}

	salt := Salt(append(purpose.Bytes(), randBytes...))
	return salt, salt.Validate()
}

// SaltPurpose distinguishes between different use cases for which
// a salt should be used, distinguishing between algorithms, key
// lengths and operation types.
type SaltPurpose struct {
	Algo      SaltAlgo
	Operation SaltOperation
}

func newSaltPurpose(algo SaltAlgo, operation SaltOperation) SaltPurpose {
	return SaltPurpose{
		Algo:      algo,
		Operation: operation,
	}
}

// Bytes returns the byte representation of a salt purpose.
func (sp SaltPurpose) Bytes() []byte {
	return []byte{byte(sp.Algo), byte(sp.Operation)}
}

// Validate validates a salt purpose.
func (sp SaltPurpose) Validate() error {
	err := sp.Algo.Validate()
	if err != nil {
		return err
	}

	return sp.Operation.Validate()
}

// Verify verifies whether a salt is intended for a given algorithm,
// key length, and operation type, returning an error when it is not.
func (sp SaltPurpose) Verify(keyLen int, alg string, operation SaltOperation) error {
	err := sp.Validate()
	if err != nil {
		return err
	}

	if sp.Operation != operation {
		return ErrInvalidSaltOperation
	}

	return sp.VerifyAlgo(keyLen, alg)
}

// VerifyAlgo verifies whether a salt is intended for a given
// algorithm and key length, returning an error when it is not.
func (sp SaltPurpose) VerifyAlgo(keyLen int, alg string) error {
	err := sp.Validate()
	if err != nil {
		return err
	}

	if sp.Algo.KeyLen() == keyLen &&
		sp.Algo.Alg() == alg {
		return nil
	}

	return ErrInvalidSaltAlgo
}

// SaltAlgo distinguishes between different algorithms and
// different key lengths for which the salt should be used.
type SaltAlgo byte

// Salt algorithms
const (
	// SaltAlgoNone is defined here so it isn't left open
	// for potential initialization errors. Note that it is
	// not a valid algorithm.
	SaltAlgoNone      = 0x00
	SaltAlgoAES128GCM = 0x01
	SaltAlgoAES196GCM = 0x02
	SaltAlgoAES256GCM = 0x03
)

// saltAlgoForKeyLen maps a key length n to a salt purpose.
func saltAlgoForKeyLen(n int) SaltAlgo {
	switch n {
	case 16:
		return SaltAlgoAES128GCM
	case 24:
		return SaltAlgoAES196GCM
	case 32:
		return SaltAlgoAES256GCM
	default:
		return SaltAlgoNone
	}
}

// Validate validates a salt algorithm.
func (sa SaltAlgo) Validate() error {
	switch sa {
	case SaltAlgoAES128GCM,
		SaltAlgoAES196GCM,
		SaltAlgoAES256GCM:
		return nil
	default:
		return ErrInvalidSaltAlgo
	}
}

// KeyLen returns the key length to be used for the salt's designated algorithm.
func (sa SaltAlgo) KeyLen() int {
	switch sa {
	case SaltAlgoAES128GCM:
		return 16
	case SaltAlgoAES196GCM:
		return 24
	case SaltAlgoAES256GCM:
		return 32
	default:
		return 0
	}
}

// Alg returns the algorithm to be used for the salt's designated algorithm.
func (sa SaltAlgo) Alg() string {
	switch sa {
	case SaltAlgoAES128GCM,
		SaltAlgoAES196GCM,
		SaltAlgoAES256GCM:
		return "aesgcm"
	default:
		return ""
	}
}

// SaltOperation distinguishes between different operations for
// which a salt should be used.
type SaltOperation byte

// Salt operations
const (
	// SaltOperationNone is defined here so it isn't left open
	// for potential initialization errors. Note that it is
	// not a valid operation.
	SaltOperationNone                      = 0x00
	SaltOperationLocalCredentialEncryption = 0x01
	SaltOperationHTTPAuthentication        = 0x02
)

func (so SaltOperation) String() string {
	switch so {
	case SaltOperationLocalCredentialEncryption:
		return "local_credential_encryption"
	case SaltOperationHTTPAuthentication:
		return "http_authentication"
	default:
		return ""
	}
}

// Validate validates a salt operation.
func (so SaltOperation) Validate() error {
	switch so {
	case SaltOperationLocalCredentialEncryption, SaltOperationHTTPAuthentication:
		return nil
	default:
		return ErrInvalidSaltOperation
	}
}
