package goauth

type Token struct {
	CredentialsBase
	Token string
}

var _ Credentials = &Token{}
