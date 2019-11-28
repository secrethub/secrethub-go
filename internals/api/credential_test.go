package api

import (
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestCreateCredentialRequest_Validate(t *testing.T) {
	description := "Personal laptop credential"

	cases := map[string]struct {
		req CreateCredentialRequest
		err error
	}{
		"success": {
			req: CreateCredentialRequest{
				Description: &description,
				Type:        CredentialTypeKey,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"success without description": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeKey,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"success including account key": {
			req: CreateCredentialRequest{
				Description: &description,
				Type:        CredentialTypeKey,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
				AccountKey: &CreateAccountKeyRequest{
					EncryptedPrivateKey: NewEncryptedDataAESGCM([]byte("encrypted"), []byte("nonce"), 96, NewEncryptionKeyLocal(256)),
					PublicKey:           []byte("public-key"),
				},
			},
			err: nil,
		},
		"including invalid account key": {
			req: CreateCredentialRequest{
				Description: &description,
				Type:        CredentialTypeKey,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
				AccountKey:  &CreateAccountKeyRequest{},
			},
			err: ErrInvalidPublicKey,
		},
		"success without Description": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeKey,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: nil,
		},
		"no fingerprint": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeKey,
				Description: &description,
				Verifier:    []byte("verifier"),
			},
			err: ErrMissingField("fingerprint"),
		},
		"invalid fingerprint": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeKey,
				Description: &description,
				Fingerprint: "not-valid",
				Verifier:    []byte("verifier"),
			},
			err: ErrInvalidFingerprint,
		},
		"empty verifier": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeKey,
				Description: &description,
				Fingerprint: "fingerprint",
				Verifier:    nil,
			},
			err: ErrMissingField("verifier"),
		},
		"empty type": {
			req: CreateCredentialRequest{
				Description: &description,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
			},
			err: ErrMissingField("type"),
		},
		"invalid type": {
			req: CreateCredentialRequest{
				Description: &description,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
				Type:        CredentialType("invalid"),
			},
			err: ErrInvalidCredentialType,
		},
		"success aws": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeAWS,
				Fingerprint: "81e5c41692870d5f59875aa6bbd18d0099140795cb968824a2279d3d35095907",
				Verifier:    []byte("arn:aws:iam::123456:role/path/to/role"),
				Proof:       &CredentialProofAWS{},
				Metadata: map[string]string{
					CredentialMetadataAWSRole:   "arn:aws:iam::123456:role/path/to/role",
					CredentialMetadataAWSKMSKey: "arn:aws:kms:us-east-1:123456:key/12345678-1234-1234-1234-123456789012",
				},
			},
			err: nil,
		},
		"aws role missing": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeAWS,
				Fingerprint: "81e5c41692870d5f59875aa6bbd18d0099140795cb968824a2279d3d35095907",
				Verifier:    []byte("arn:aws:iam::123456:role/path/to/role"),
				Proof:       &CredentialProofAWS{},
				Metadata: map[string]string{
					CredentialMetadataAWSKMSKey: "arn:aws:kms:us-east-1:123456:key/12345678-1234-1234-1234-123456789012",
				},
			},
			err: ErrMissingMetadata(CredentialMetadataAWSRole, CredentialTypeAWS),
		},
		"aws kms key missing": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeAWS,
				Fingerprint: "81e5c41692870d5f59875aa6bbd18d0099140795cb968824a2279d3d35095907",
				Verifier:    []byte("arn:aws:iam::123456:role/path/to/role"),
				Proof:       &CredentialProofAWS{},
				Metadata: map[string]string{
					CredentialMetadataAWSRole: "arn:aws:iam::123456:role/path/to/role",
				},
			},
			err: ErrMissingMetadata(CredentialMetadataAWSKMSKey, CredentialTypeAWS),
		},
		"extra metadata": {
			req: CreateCredentialRequest{
				Description: &description,
				Type:        CredentialTypeKey,
				Fingerprint: "88c9eae68eb300b2971a2bec9e5a26ff4179fd661d6b7d861e4c6557b9aaee14",
				Verifier:    []byte("verifier"),
				Metadata: map[string]string{
					"foo": "bar",
				},
			},
			err: ErrUnknownMetadataKey("foo"),
		},
		"extra metadata aws": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeAWS,
				Fingerprint: "81e5c41692870d5f59875aa6bbd18d0099140795cb968824a2279d3d35095907",
				Verifier:    []byte("arn:aws:iam::123456:role/path/to/role"),
				Proof:       &CredentialProofAWS{},
				Metadata: map[string]string{
					CredentialMetadataAWSRole:   "arn:aws:iam::123456:role/path/to/role",
					CredentialMetadataAWSKMSKey: "arn:aws:kms:us-east-1:123456:key/12345678-1234-1234-1234-123456789012",
					"foo":                       "bar",
				},
			},
			err: ErrUnknownMetadataKey("foo"),
		},
		"backup code success": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeBackupCode,
				Fingerprint: "69cf01c1e969b4430ca1b08ede7dab5f91a64a306e321f0348667446e1b3597e",
				Verifier:    []byte("DdAaVTKxoYgxzWY2UWrdl1xHOOv4ZUozra4Vm8WGxmU="),
				Proof:       &CredentialProofBackupCode{},
				Metadata:    map[string]string{},
			},
			err: nil,
		},
		"backup code too short verifier": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeBackupCode,
				Fingerprint: "69cf01c1e969b4430ca1b08ede7dab5f91a64a306e321f0348667446e1b3597e",
				Verifier:    []byte("DdAaVTKxoYgxzWY2UWrdl1OOv4ZUozra4Vm8WGxmU="),
				Proof:       &CredentialProofBackupCode{},
				Metadata:    map[string]string{},
			},
			err: ErrInvalidVerifier,
		},
		"backup code non base64 verifier": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeBackupCode,
				Fingerprint: "69cf01c1e969b4430ca1b08ede7dab5f91a64a306e321f0348667446e1b3597e",
				Verifier:    []byte("DdAaVTKxoYgxzWY2UWrdl1OOv4ZUozra4Vm8WGxm&="),
				Proof:       &CredentialProofBackupCode{},
				Metadata:    map[string]string{},
			},
			err: ErrInvalidVerifier,
		},
		"backup code with metadata": {
			req: CreateCredentialRequest{
				Type:        CredentialTypeBackupCode,
				Fingerprint: "69cf01c1e969b4430ca1b08ede7dab5f91a64a306e321f0348667446e1b3597e",
				Verifier:    []byte("DdAaVTKxoYgxzWY2UWrdl1xHOOv4ZUozra4Vm8WGxmU="),
				Proof:       &CredentialProofBackupCode{},
				Metadata: map[string]string{
					CredentialMetadataAWSKMSKey: "test",
				},
			},
			err: ErrInvalidMetadataKey(CredentialMetadataAWSKMSKey, CredentialTypeBackupCode),
		},
	}

	for Description, tc := range cases {
		t.Run(Description, func(t *testing.T) {
			// Do
			err := tc.req.Validate()

			// Assert
			assert.Equal(t, err, tc.err)
		})
	}
}
