package api

// EncryptionMetadataAESGCM is the metadata used by the AES-GCM encryption algorithm.
type EncryptionMetadataAESGCM struct {
	Nonce []byte `json:"nonce"`
}

// Validate checks whether the EncryptionMetadataAESGCM is valid.
func (m EncryptionMetadataAESGCM) Validate() error {
	if m.Nonce == nil {
		return ErrMissingField("nonce")
	}
	return nil
}
