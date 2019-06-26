package api

// EncryptionParametersAESGCM are the parameters used by the AES-GCM encryption algorithm.
type EncryptionParametersAESGCM struct {
	NonceLength *int `json:"nonce_length"`
}

// Validate checks whether the EncryptionParametersAESGCM is valid.
func (EncryptionParametersAESGCM) Validate() error {
	return nil
}

// EncryptionParametersRSAOAEP are the parameters used by the RSA-OAEP encryption algorithm.
type EncryptionParametersRSAOAEP struct {
	HashingAlgorithm HashingAlgorithm `json:"hashing_algorithm"`
}

// Validate checks whether the EncryptionParametersRSAOAEP is valid.
func (EncryptionParametersRSAOAEP) Validate() error {
	return nil
}
