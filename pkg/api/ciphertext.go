package api

// Errors
// These will be removed after the next server-release,
// as they are then no longer returned from the server.
var (
	ErrUnknownAlgorithm  = errAPI.Code("unknown_algorithm").Error("algorithm of the encoded ciphertext is invalid")
	ErrInvalidCiphertext = errAPI.Code("invalid_ciphertext").Error("cannot encode invalid ciphertext")
	ErrInvalidMetadata   = errAPI.Code("invalid_metadata").Error("metadata of encrypted key is invalid")
)
