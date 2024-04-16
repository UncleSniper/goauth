package goauth

type UserIDPrincipal[UidT any] struct {
	PrincipalBase
	UID UidT
}

var _ Principal = &UserIDPrincipal[uint64]{}
