package goauth

type NullPrincipal struct {
	PrincipalBase
}

var _ Principal = &NullPrincipal{}
