package goauth

type NullCredentials struct {
	CredentialsBase
}

var _ Credentials = &NullCredentials{}
