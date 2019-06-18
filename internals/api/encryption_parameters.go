package api

type EncryptionParametersAESGCM struct {
	NonceLength *int `json:"nonce_length"`
}

func (EncryptionParametersAESGCM) Validate() error {
	return nil
}

type EncryptionParametersRSAOAEP struct {
	HashingAlgorithm HashingAlgorithm `json:"hashing_algorithm"`
}

func (EncryptionParametersRSAOAEP) Validate() error {
	return nil
}

type EncryptionParametersAWSKMS struct{}

func (EncryptionParametersAWSKMS) Validate() error {
	return nil
}
