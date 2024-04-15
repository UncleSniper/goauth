package goauth

type Authenticator[ContextT any] interface {
	Authenticate(ContextT, Credentials) (Principal, error)
}
