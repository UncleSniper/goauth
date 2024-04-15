package goauth

type UserID[UidT any] struct {
	PrincipalBase
	UID UidT
}

var _ Principal = &UserID[uint64]{}
