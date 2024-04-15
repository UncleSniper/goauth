package goauth

type Password struct {
	CredentialsBase
	Password string
}

var _ Credentials = &Password{}
