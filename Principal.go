package goauth

type Principal interface {
	Domain() DomainID
}

type PrincipalBase struct {
	DomainID DomainID
}

func(base *PrincipalBase) Domain() DomainID {
	return base.DomainID
}
