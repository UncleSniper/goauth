package goauth

type Authenticator[ContextT any] interface {
	Authenticate(ContextT, Credentials) (Principal, error)
}

func CallbackOfAuthenticator[ContextT any, FlagsT ~uint32, CredentialsT Credentials](
	auth Authenticator[ContextT],
) (callback func(FlagsT, ContextT, CredentialsT) (Principal, error)) {
	if auth != nil {
		callback = func(flags FlagsT, context ContextT, credentials CredentialsT) (Principal, error) {
			return auth.Authenticate(context, credentials)
		}
	}
	return
}
