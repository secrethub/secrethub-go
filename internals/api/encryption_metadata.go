package api

type EncryptionMetadataAESGCM struct {
	Nonce []byte `json:"nonce"`
}

func (EncryptionMetadataAESGCM) Validate() error {
	return nil
}

type EncryptionMetadataRSAOEAP struct{}

func (EncryptionMetadataRSAOEAP) Validate() error {
	return nil
}

type EncryptionMetadataAWSKMS struct{}

func (EncryptionMetadataAWSKMS) Validate() error {
	return nil
}
