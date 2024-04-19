package goauth

type DispatchingAuthFlags uint32

const (
	DISPAUTHFL_DISALLOW_GENERIC_PROTOCOL = (1 << iota)
	DISPAUTHFL_DISALLOW_GENERIC_DOMAIN
)

type DispatchingAuthenticator[ContextT any] struct {
	Flags DispatchingAuthFlags
	children map[ProtoID]map[DomainID]func(DispatchingAuthFlags, ContextT, Credentials) (Principal, error)
}

func(auth *DispatchingAuthenticator[ContextT]) SetChild(
	proto ProtoID,
	domain DomainID,
	child func(DispatchingAuthFlags, ContextT, Credentials) (Principal, error),
) {
	if auth.children == nil {
		if child == nil {
			return
		}
		auth.children = make(map[ProtoID]map[DomainID]func(
			DispatchingAuthFlags,
			ContextT,
			Credentials,
		) (Principal, error))
	}
	if child == nil {
		byProto, ok := auth.children[proto]
		if !ok {
			return
		}
		delete(byProto, domain)
	} else {
		byProto, ok := auth.children[proto]
		if !ok {
			byProto = make(map[DomainID]func(DispatchingAuthFlags, ContextT, Credentials) (Principal, error))
			auth.children[proto] = byProto
		}
		byProto[domain] = child
	}
}

func(auth *DispatchingAuthenticator[ContextT]) Authenticate(
	context ContextT,
	credentials Credentials,
) (Principal, error) {
	var child func(DispatchingAuthFlags, ContextT, Credentials) (Principal, error)
	if auth.children != nil && credentials != nil {
		proto := credentials.Protocol()
		if proto != UNKNOWN_PROTO_ID {
			byProto, ok := auth.children[proto]
			if !ok && (auth.Flags & DISPAUTHFL_DISALLOW_GENERIC_PROTOCOL) == 0 {
				byProto, ok = auth.children[UNKNOWN_PROTO_ID]
			}
			if ok && byProto != nil {
				domain := credentials.Domain()
				if domain != NOWHERE_DOMAIN_ID {
					child, ok = byProto[domain]
					if !ok && (auth.Flags & DISPAUTHFL_DISALLOW_GENERIC_DOMAIN) == 0 {
						child, ok = byProto[NOWHERE_DOMAIN_ID]
					}
					if !ok {
						child = nil
					}
				}
			}
		}
	}
	if child == nil {
		return nil, &UnmappedAuthenticatorError {
			Protocol: credentials.Protocol(),
			Domain: credentials.Domain(),
		}
	}
	return child(auth.Flags, context, credentials)
}
