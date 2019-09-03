// Package uuid is a utility package to standardize and abstract away how UUIDs are generated and used.
package uuid

import (
	gid "github.com/satori/go.uuid"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	errInvalidUUID    = errio.Namespace("uuid").Code("invalid")
	ErrInvalidUUIDErr = errInvalidUUID.ErrorPref("invalid uuid: %s")
)

// UUID is a wrapper around go.uuid.UUID
type UUID struct {
	gid.UUID
}

// New generates a new UUID.
func New() *UUID {
	id := gid.NewV4()
	return &UUID{id}
}

// FromString reads a UUID from a string
func FromString(str string) (*UUID, error) {
	id, err := gid.FromString(str)
	if err != nil {
		return nil, ErrInvalidUUIDErr(err)
	}
	return &UUID{id}, nil
}

// ToString converts UUID into string
func (u *UUID) ToString() string {
	return u.UUID.String()
}

// IsZero returns true if the UUID is equal to the zero-value.
func (u *UUID) IsZero() bool {
	return u.UUID == gid.UUID([gid.Size]byte{0})
}

// Equal returns true if both argument uuids contain the same value.
func Equal(a *UUID, b *UUID) bool {
	return gid.Equal(a.UUID, b.UUID)
}

// Validate validates a uuid string is a valid UUID.
func Validate(str string) error {
	_, err := FromString(str)
	return err
}

// IsErrInvalidUUID returns whether the given error is returned for an invalid uuid.
func IsErrInvalidUUID(err error) bool {
	publicErr, ok := err.(errio.PublicError)
	if !ok {
		return false
	}
	return publicErr.Namespace == errInvalidUUID.Namespace && publicErr.Code == errInvalidUUID.Code
}
