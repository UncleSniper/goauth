package goauth

type ChainAuthenticator[ContextT any] struct {
	Outer Authenticator[ContextT]
	Inner Authenticator[ContextT]
}

func(auth *ChainAuthenticator[ContextT]) Authenticate(
	context ContextT,
	credentials Credentials,
) (result Principal, err error) {
	return ChainAuthenticate[ContextT](auth.Outer, auth.Inner, context, credentials)
}

func ChainAuthenticate[ContextT any](
	outer Authenticator[ContextT],
	inner Authenticator[ContextT],
	context ContextT,
	credentials Credentials,
) (result Principal, err error) {
	if outer == nil {
		err = MissingAuthenticatorError{}
		return
	}
	intermediate, outerErr := outer.Authenticate(context, credentials)
	if outerErr != nil {
		err = outerErr
		return
	}
	if intermediate == nil {
		return
	}
	cred, ok := intermediate.(*CredentialsPrincipal)
	if !ok {
		err = MakeUnexpectedPrincipalTypeError(&CredentialsPrincipal{}, intermediate, outer)
		return
	}
	if inner == nil {
		err = MissingAuthenticatorError{}
		return
	}
	result, err = inner.Authenticate(context, cred.Credentials)
	return
}

var _ Authenticator[int] = &ChainAuthenticator[int]{}
