package api

type EncryptionMetadataAESGCM struct {
	Nonce []byte `json:"nonce"`
}

func (EncryptionMetadataAESGCM) Validate() error {
	return nil
}
