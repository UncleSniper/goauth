package goauth

import (
	"reflect"
)

type CredentialsTypeAuthenticator[ContextT any, CredentialsT Credentials] struct {
	Converter func(ContextT, Credentials) (CredentialsT, error)
	ErrorFactory func(ContextT, Credentials, reflect.Type) error
	Downstream Authenticator[ContextT]
	PrincipalFactory func(ContextT, CredentialsT) (Principal, error)
	DomainID DomainID
}

func(auth *CredentialsTypeAuthenticator[ContextT, CredentialsT]) Authenticate(
	context ContextT,
	credentials Credentials,
) (result Principal, err error) {
	var converted CredentialsT
	if auth.Converter != nil {
		converted, err = auth.Converter(context, credentials)
		if err != nil {
			return
		}
	} else {
		var ok bool
		converted, ok = credentials.(CredentialsT)
		if !ok {
			if auth.ErrorFactory != nil {
				err = auth.ErrorFactory(context, credentials, reflect.TypeOf(new(CredentialsT)).Elem())
			}
			if err == nil {
				var ftype string
				if credentials != nil {
					ftype = reflect.TypeOf(credentials).String()
				}
				err = &UnexpectedCredentialsTypeError {
					Expected: reflect.TypeOf(new(CredentialsT)).Elem().String(),
					Found: ftype,
				}
				return
			}
		}
	}
	if auth.Downstream != nil {
		result, err = auth.Downstream.Authenticate(context, converted)
	} else {
		if auth.PrincipalFactory != nil {
			result, err = auth.PrincipalFactory(context, converted)
		}
		if err == nil && result == nil {
			result = &NullPrincipal {
				PrincipalBase: PrincipalBase {
					DomainID: auth.DomainID,
				},
			}
		}
	}
	return
}

var _ Authenticator[int] = &CredentialsTypeAuthenticator[int, *PasswordCredentials]{}
