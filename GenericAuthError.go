package goauth

type GenericAuthError struct {
	Message string
	BlameUser bool
}

func(err *GenericAuthError) Error() string {
	if len(err.Message) > 0 {
		return err.Message
	}
	return "Authentication failed"
}

func(err *GenericAuthError) IsUserToBlame() bool {
	return err.BlameUser
}

func MakeGenericAuthError(message string, blameUser bool) AuthError {
	return &GenericAuthError {
		Message: message,
		BlameUser: blameUser,
	}
}

var _ AuthError = &GenericAuthError{}
