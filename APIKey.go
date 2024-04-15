package goauth

type APIKey struct {
	CredentialsBase
	Key string
}

var _ Credentials = &APIKey{}
