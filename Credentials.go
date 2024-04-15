package goauth

type Credentials interface {
	Protocol() ProtoID
	Domain() DomainID
}

type CredentialsBase struct {
	ProtoID ProtoID
	DomainID DomainID
}

func(base *CredentialsBase) Protocol() ProtoID {
	return base.ProtoID
}

func(base *CredentialsBase) Domain() DomainID {
	return base.DomainID
}
