package secrethub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/assert"
)

var (
	foo                  = "foo"
	fooEncoded           = "Zm9v"
	exampleHeader        = map[string]interface{}{"type": "test"}
	exampleHeaderEncoded = "eyJ0eXBlIjoidGVzdCJ9"
)

// RunArmorInterfaceTest tests whether an Armorer and corresponding Unarmorer
// interfaces work correctly.
func RunArmorInterfaceTest(t *testing.T, armorer PassBasedKey, unarmorer PassBasedKey) {
	t.Run("name_equality", func(t *testing.T) {
		assert.Equal(t, armorer.Name(), unarmorer.Name())
	})

	t.Run("encryption", func(t *testing.T) {
		expected := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

		armored, header, err := armorer.Encrypt(expected)
		assert.OK(t, err)

		if reflect.DeepEqual(armored, expected) {
			t.Errorf(
				"unexpected armored payload: %v (armored) == %v (unarmored)",
				armored,
				expected,
			)
		}

		headerBytes, err := json.Marshal(header)
		assert.OK(t, err)

		unarmored, err := unarmorer.Decrypt(armored, headerBytes)
		assert.OK(t, err)

		assert.Equal(t, unarmored, expected)
	})
}

func TestPassphraseArmoring(t *testing.T) {

	pass := []byte("Password123")
	unarmorer := NewPassphraseUnarmorer(pass)

	armorer, err := NewPassphraseArmorer(pass)
	assert.OK(t, err)

	RunArmorInterfaceTest(t, armorer, unarmorer)
}

// RunCredentialInterfaceTest tests whether a Credential interface
// works correctly.
func RunCredentialInterfaceTest(t *testing.T, credential Credential) {
	t.Run("encoding", func(t *testing.T) {
		exported := credential.Export()

		decoder := credential.Decoder()
		actual, err := decoder.Decode(exported)
		assert.OK(t, err)

		assert.Equal(t, actual, credential)
	})

	t.Run("encryption", func(t *testing.T) {
		expected := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

		ciphertext, err := credential.Wrap(expected)
		assert.OK(t, err)

		if reflect.DeepEqual(ciphertext, expected) {
			t.Errorf(
				"unexpected ciphertext: %v (ciphertext) == %v (plaintext)",
				ciphertext,
				expected,
			)
		}

		actual, err := credential.Unwrap(ciphertext)
		assert.OK(t, err)

		assert.Equal(t, actual, expected)
	})
}

func TestRSACredential(t *testing.T) {

	credential, err := generateRSACredential(1024)
	assert.OK(t, err)

	RunCredentialInterfaceTest(t, credential)
}

func TestParser(t *testing.T) {

	// Arrange
	credential, err := generateRSACredential(1024)
	assert.OK(t, err)

	payload := credential.Export()

	header := map[string]interface{}{
		"type": credential.Decoder().Name(),
	}
	headerBytes, err := json.Marshal(header)
	assert.OK(t, err)
	raw := fmt.Sprintf(
		"%s.%s",
		DefaultCredentialEncoding.EncodeToString(headerBytes),
		DefaultCredentialEncoding.EncodeToString(payload),
	)

	headerArmored := map[string]interface{}{
		"type": credential.Decoder().Name(),
		"enc":  "scrypt",
	}
	headerArmoredBytes, err := json.Marshal(headerArmored)
	assert.OK(t, err)
	rawArmored := fmt.Sprintf(
		"%s.%s",
		DefaultCredentialEncoding.EncodeToString(headerArmoredBytes),
		DefaultCredentialEncoding.EncodeToString(payload), // payload isn't actually armored but that does not matter for the parser.
	)

	headerTypeNotSet, err := json.Marshal(map[string]interface{}{"foo": "bar"})
	assert.OK(t, err)

	headerUnsupportedType, err := json.Marshal(map[string]interface{}{"type": "unsupported"})
	assert.OK(t, err)

	cases := map[string]struct {
		raw      string
		expected *EncodedCredential
		err      error
	}{
		"valid_rsa": {
			raw: raw,
			expected: &EncodedCredential{
				Raw:       raw,
				Header:    header,
				RawHeader: headerBytes,
				Payload:   payload,
				Armor:     "",
				Decoder:   credential.Decoder(),
			},
			err: nil,
		},
		"valid_rsa_armored": {
			raw: rawArmored,
			expected: &EncodedCredential{
				Raw:       rawArmored,
				Header:    headerArmored,
				RawHeader: headerArmoredBytes,
				Payload:   payload,
				Armor:     "scrypt",
				Decoder:   credential.Decoder(),
			},
			err: nil,
		},
		"header_one_segment": {
			raw:      DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
			expected: nil,
			err:      ErrInvalidNumberOfCredentialSegments(1),
		},
		"header_three_segments": {
			raw: fmt.Sprintf(
				"%s.%s.%s",
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
			),
			expected: nil,
			err:      ErrInvalidNumberOfCredentialSegments(3),
		},
		"header_not_base64": {
			raw:      fmt.Sprintf("#not_base64.%s", DefaultCredentialEncoding.EncodeToString(payload)),
			expected: nil,
			err:      ErrCannotDecodeCredentialHeader("illegal base64 data at input byte 0"),
		},
		"header_not_json": {
			raw: fmt.Sprintf(
				"%s.%s",
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
			),
			expected: nil,
			err:      ErrCannotDecodeCredentialHeader("cannot unmarshal json: invalid character '\\x00' looking for beginning of value"),
		},
		"header_type_not_set": {
			raw: fmt.Sprintf(
				"%s.%s",
				DefaultCredentialEncoding.EncodeToString(headerTypeNotSet),
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
			),
			expected: nil,
			err:      ErrInvalidCredentialHeaderField("type"),
		},
		"header_unsupported_type": {
			raw: fmt.Sprintf(
				"%s.%s",
				DefaultCredentialEncoding.EncodeToString(headerUnsupportedType),
				DefaultCredentialEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
			),
			expected: nil,
			err:      ErrUnsupportedCredentialType("unsupported"),
		},
		"payload_not_base64": {
			raw: fmt.Sprintf(
				"%s.#not_base64",
				DefaultCredentialEncoding.EncodeToString(headerBytes),
			),
			expected: nil,
			err:      ErrCannotDecodeCredentialPayload("illegal base64 data at input byte 0"),
		},
	}

	parser := NewCredentialParser(DefaultCredentialDecoders)

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, err := parser.Parse(tc.raw)

			// Assert
			assert.Equal(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, actual, tc.expected)
			}
		})
	}
}

func TestEncodeCredential(t *testing.T) {

	// Arrange
	cred, err := generateRSACredential(1024)
	assert.OK(t, err)

	parser := NewCredentialParser(DefaultCredentialDecoders)

	// Act
	raw, err := EncodeCredential(cred)
	assert.OK(t, err)

	parsed, err := parser.Parse(raw)
	assert.OK(t, err)

	decoded, err := parsed.Decode()
	assert.OK(t, err)

	// Assert
	assert.Equal(t, cred, decoded)
}

func TestEncodeArmoredCredential(t *testing.T) {

	// Arrange
	cred, err := generateRSACredential(1024)
	assert.OK(t, err)

	parser := NewCredentialParser(DefaultCredentialDecoders)

	pass := []byte("Password123")
	unarmorer := NewPassphraseUnarmorer(pass)

	armorer, err := NewPassphraseArmorer(pass)
	assert.OK(t, err)

	// Act
	raw, err := EncodeArmoredCredential(cred, armorer)
	assert.OK(t, err)

	parsed, err := parser.Parse(raw)
	assert.OK(t, err)

	decoded, err := parsed.DecodeArmored(unarmorer)
	assert.OK(t, err)

	// Assert
	assert.Equal(t, cred, decoded)
}

func TestEncodeCredentialPartsToString(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		header   map[string]interface{}
		payload  []byte
		expected string
		err      error
	}{
		"success": {
			header:   exampleHeader,
			payload:  []byte(foo),
			expected: fmt.Sprintf("%s.%s", exampleHeaderEncoded, fooEncoded),
		},
		"nil_header": {
			header:  nil,
			payload: []byte(foo),
			err:     ErrEmptyCredentialHeader,
		},
		"empty_header": {
			header:  make(map[string]interface{}),
			payload: []byte(foo),
			err:     ErrEmptyCredentialHeader,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, err := encodeCredentialPartsToString(tc.header, tc.payload)
			assert.Equal(t, err, tc.err)

			// Assert
			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestCredentialIsEncrypted(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		armor    string
		expected bool
	}{
		"empty": {
			armor:    "",
			expected: false,
		},
		"armored": {
			armor:    "scrypt",
			expected: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cred := &EncodedCredential{
				Armor: tc.armor,
			}

			// Act
			actual := cred.IsEncrypted()

			// Assert
			assert.Equal(t, actual, tc.expected)
		})
	}
}

// TestBase64NoPadding tests the assumption that base64 works fine
// if you consistently disable padding and don't concatenate strings.
func TestBase64NoPaddingAssumption(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		input    string
		expected string
	}{
		"empty": {
			input:    "",
			expected: "",
		},
		"one_byte": {
			input:    "f",
			expected: "Zg",
		},
		"two_byte": {
			input:    "fo",
			expected: "Zm8",
		},
		"three_byte": {
			input:    "foo",
			expected: "Zm9v",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(tc.input))

			decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded)
			assert.OK(t, err)

			// Assert
			assert.Equal(t, encoded, tc.expected)
			assert.Equal(t, string(decoded), tc.input)
		})
	}
}
