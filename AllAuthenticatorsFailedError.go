package goauth

import (
	"fmt"
	"strings"
)

type AllAuthenticatorsFailedError struct {
	Errors []error
}

func(err *AllAuthenticatorsFailedError) Error() string {
	var builder strings.Builder
	builder.WriteString("No allowed authentication succeeded")
	var had bool
	for index, child := range err.Errors {
		if child == nil {
			continue
		}
		if had {
			builder.WriteString(", ")
		} else {
			builder.WriteString(" (")
			had = true
		}
		builder.WriteString(fmt.Sprintf("#%d = ", index))
		builder.WriteString(child.Error())
	}
	if had {
		builder.WriteRune(')')
	}
	return builder.String()
}

func(err *AllAuthenticatorsFailedError) IsUserToBlame() bool {
	for _, child := range err.Errors {
		if child == nil {
			continue
		}
		authErr, ok := child.(AuthError)
		isSystemToBlame := !ok || !authErr.IsUserToBlame()
		if isSystemToBlame {
			return false
		}
	}
	return true
}

var _ AuthError = &AllAuthenticatorsFailedError{}
