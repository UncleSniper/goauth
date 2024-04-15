package goauth

type AnyAuthenticator[ContextT any] struct {
	Authenticators []Authenticator[ContextT]
}

func(auth *AnyAuthenticator[ContextT]) Authenticate(
	context ContextT,
	credentials Credentials,
) (result Principal, err error) {
	var errors []error
	var had bool
	for _, child := range auth.Authenticators {
		if child == nil {
			continue
		}
		principal, childErr := child.Authenticate(context, credentials)
		if childErr != nil {
			if !had {
				errors = append(errors, childErr)
			}
			continue
		}
		if principal != nil {
			result = principal
			return
		}
		had = true
	}
	if !had {
		err = &AllAuthenticatorsFailedError {
			Errors: errors,
		}
	}
	return
}

var _ Authenticator[int] = &AnyAuthenticator[int]{}
