package goauth

type MissingAuthenticatorError struct {}

func(err MissingAuthenticatorError) Error() string {
	return "Missing authenticator fails by definition"
}

func(err MissingAuthenticatorError) IsUserToBlame() bool {
	return false
}

var _ AuthError = MissingAuthenticatorError{}
