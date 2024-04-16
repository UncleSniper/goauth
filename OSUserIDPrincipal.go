package goauth

type OSUserIDPrincipal[UidT any, GidT any] struct {
	PrincipalBase
	UID UidT
	GID GidT
	GIDs []GidT
}

var _ Principal = &OSUserIDPrincipal[uint64, float32]{}
