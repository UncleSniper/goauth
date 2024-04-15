package goauth

type CredentialsPrincipal struct {
	PrincipalBase
	Credentials Credentials
}

var _ Principal = &CredentialsPrincipal{}
