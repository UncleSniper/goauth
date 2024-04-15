package goauth

import (
	"strings"
	"reflect"
)

type UnexpectedPrincipalTypeError struct {
	Expected string
	Found string
	Authenticator string
}

func(err *UnexpectedPrincipalTypeError) Error() string {
	var builder strings.Builder
	builder.WriteString("Unexpected credentials type")
	if len(err.Authenticator) > 0 {
		builder.WriteString(" arising from authenticator ")
		builder.WriteString(err.Authenticator)
	}
	var had bool
	if len(err.Expected) > 0 {
		builder.WriteString(": Expected ")
		had = true
		builder.WriteString(err.Expected)
	}
	if len(err.Found) > 0 {
		if had {
			builder.WriteString(", but got ")
		} else {
			builder.WriteString(": Got ")
		}
		builder.WriteString(err.Found)
	}
	return builder.String()
}

func(err *UnexpectedPrincipalTypeError) IsUserToBlame() bool {
	return false
}

func MakeUnexpectedPrincipalTypeError(expected any, found any, authenticator any) AuthError {
	err := &UnexpectedPrincipalTypeError {}
	etype := reflect.TypeOf(expected)
	if etype != nil {
		err.Expected = etype.String()
	}
	ftype := reflect.TypeOf(found)
	if ftype != nil {
		err.Found = ftype.String()
	}
	atype := reflect.TypeOf(authenticator)
	if atype != nil {
		err.Authenticator = atype.String()
	}
	return err
}

var _ AuthError = &UnexpectedPrincipalTypeError{}
