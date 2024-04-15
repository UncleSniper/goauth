package goauth

type UsernameAndPassword struct {
	CredentialsBase
	Username string
	Password string
}

var _ Credentials = &UsernameAndPassword{}
