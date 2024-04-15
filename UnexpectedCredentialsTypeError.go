package goauth

import (
	"strings"
	"reflect"
)

type UnexpectedCredentialsTypeError struct {
	Expected string
	Found string
}

func(err *UnexpectedCredentialsTypeError) Error() string {
	var builder strings.Builder
	builder.WriteString("Unexpected credentials type")
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

func(err *UnexpectedCredentialsTypeError) IsUserToBlame() bool {
	return false
}

func MakeUnexpectedCredentialsTypeError(expected any, found any) AuthError {
	err := &UnexpectedCredentialsTypeError {}
	etype := reflect.TypeOf(expected)
	if etype != nil {
		err.Expected = etype.String()
	}
	ftype := reflect.TypeOf(found)
	if ftype != nil {
		err.Found = ftype.String()
	}
	return err
}

var _ AuthError = &UnexpectedCredentialsTypeError{}
