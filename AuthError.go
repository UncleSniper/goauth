package goauth

type AuthError interface {
	error
	IsUserToBlame() bool
}
