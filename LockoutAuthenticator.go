package goauth

type LockoutAuthenticator[ContextT any] struct {
	ErrorFactory func() error
}

func StaticErrorFactory(theError AuthError) func() AuthError {
	return func() AuthError {
		return theError
	}
}

func(auth LockoutAuthenticator[ContextT]) Authenticate(ContextT, Credentials) (result Principal, err error) {
	if auth.ErrorFactory != nil {
		err = auth.ErrorFactory()
	}
	if err == nil {
		err = LockoutAuthError{}
	}
	return
}

type LockoutAuthError struct {}

func(err LockoutAuthError) Error() string {
	return "Authentication against lockout authenticator always fails"
}

func(err LockoutAuthError) IsUserToBlame() bool {
	return false
}
