package goauth

type OSUserIDCredentials[UidT any, GidT any] struct {
	CredentialsBase
	UID UidT
	GID GidT
	GIDs []GidT
}

var _ Credentials = &OSUserIDCredentials[uint64, float32]{}
