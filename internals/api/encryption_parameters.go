package api

// Errors
var (
	ErrInvalidNonceLength      = errAPI.Code("invalid_nonce_length").Error("invalid nonce length provided")
	ErrInvalidHashingAlgorithm = errAPI.Code("invalid_hashing_algorithm").Error("invalid hashing algorithm provided")
)

// EncryptionParametersAESGCM are the parameters used by the AES-GCM encryption algorithm.
type EncryptionParametersAESGCM struct {
	NonceLength int `json:"nonce_length"`
}

// Validate checks whether the EncryptionParametersAESGCM is valid.
func (p EncryptionParametersAESGCM) Validate() error {
	if p.NonceLength == 0 {
		return ErrMissingField("nonce_length")
	}
	if p.NonceLength < 96 {
		return ErrInvalidNonceLength
	}
	return nil
}

// EncryptionParametersRSAOAEP are the parameters used by the RSA-OAEP encryption algorithm.
type EncryptionParametersRSAOAEP struct {
	HashingAlgorithm HashingAlgorithm `json:"hashing_algorithm"`
}

// Validate checks whether the EncryptionParametersRSAOAEP is valid.
func (p EncryptionParametersRSAOAEP) Validate() error {
	if p.HashingAlgorithm == "" {
		return ErrMissingField("hashing_algorithm")
	}
	if p.HashingAlgorithm != HashingAlgorithmSHA256 {
		return ErrInvalidHashingAlgorithm
	}
	return nil
}
