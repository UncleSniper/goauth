package goauth

import (
	"fmt"
	"strings"
)

type OSOperationUnavailableError struct {
	Operation string
}

func(err OSOperationUnavailableError) Error() string {
	var builder strings.Builder
	builder.WriteString("OS-specific operation")
	if len(err.Operation) > 0 {
		builder.WriteString(fmt.Sprintf(" '%s'", err.Operation))
	}
	builder.WriteString(" is not available in this OS")
	return builder.String()
}

func(err OSOperationUnavailableError) IsUserToBlame() bool {
	return false
}

var _ AuthError = OSOperationUnavailableError{}
