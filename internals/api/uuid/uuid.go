// Package uuid is a utility package to standardize and abstract away how UUIDs are generated and used.
package uuid

import (
	"bytes"

	gid "github.com/gofrs/uuid"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	ErrInvalidUUID = errio.Namespace("uuid").Code("invalid").ErrorPref("invalid uuid: %s")
)

// UUID is a wrapper around github.com/gofrs/uuid.UUID.
type UUID struct {
	gid.UUID
}

// New generates a new UUID.
func New() UUID {
	id, err := gid.NewV4()
	if err != nil {
		panic(err)
	}
	return UUID{id}
}

// FromString reads a UUID from a string
func FromString(str string) (UUID, error) {
	id, err := gid.FromString(str)
	if err != nil {
		return UUID{}, ErrInvalidUUID(err)
	}
	return UUID{id}, nil
}

// ToString converts UUID into string
func (u *UUID) ToString() string {
	return u.UUID.String()
}

// IsZero returns true if the UUID is equal to the zero-value.
func (u *UUID) IsZero() bool {
	return u.UUID == gid.UUID([gid.Size]byte{0})
}

// Equal returns true if both argument UUIDs contain the same value.
func Equal(a UUID, b UUID) bool {
	return bytes.Equal(a.UUID[:], b.UUID[:])
}

// Validate validates a uuid string is a valid UUID.
func Validate(str string) error {
	_, err := FromString(str)
	return err
}
