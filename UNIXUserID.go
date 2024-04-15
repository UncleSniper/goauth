package goauth

type UID uint32
type GID uint32

type UNIXUserID struct {
	PrincipalBase
	UID UID
	GID GID
	GIDs []GID
}

var _ Principal = &UNIXUserID{}
