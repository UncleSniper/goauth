package goauth

type AllAuthenticator[ContextT any] struct {
	Authenticators []Authenticator[ContextT]
	DomainID DomainID
	OneAsMulti bool
}

func(auth *AllAuthenticator[ContextT]) Authenticate(
	context ContextT,
	credentials Credentials,
) (result Principal, err error) {
	var principals []Principal
	for _, child := range auth.Authenticators {
		if child == nil {
			continue
		}
		var principal Principal
		principal, err = child.Authenticate(context, credentials)
		if err != nil {
			return
		}
		if principal != nil {
			principals = append(principals, principal)
		}
	}
	switch len(principals) {
		case 0:
			// keep nil principal
		case 1:
			if !auth.OneAsMulti && principals[0].Domain() == auth.DomainID {
				result = principals[0]
				break
			}
			fallthrough
		default:
			result = &MultiPrincipal {
				PrincipalBase: PrincipalBase {
					DomainID: auth.DomainID,
				},
				Principals: principals,
			}
	}
	return
}

var _ Authenticator[int] = &AllAuthenticator[int]{}
