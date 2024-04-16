package goauth

type UserIDCredentials[UidT any] struct {
	CredentialsBase
	UID UidT
}

var _ Credentials = &UserIDCredentials[uint64]{}
