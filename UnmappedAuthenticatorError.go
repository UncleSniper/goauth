package goauth

import (
	"fmt"
)

type UnmappedAuthenticatorError struct {
	Protocol ProtoID
	Domain DomainID
}

func(err *UnmappedAuthenticatorError) Error() string {
	protoName, ok := ProtocolName(err.Protocol)
	if !ok {
		protoName = "<unrecognized protocol>"
	}
	var domainName string
	domainName, ok = DomainName(err.Domain)
	if !ok {
		domainName = "<unrecognized domain>"
	}
	return fmt.Sprintf(
		"No authenticator mapped for protocol #%d (%s), domain #%d (%d)",
		err.Protocol,
		protoName,
		err.Domain,
		domainName,
	)
}

func(err *UnmappedAuthenticatorError) IsUserToBlame() bool {
	return false
}

var _ AuthError = &UnmappedAuthenticatorError{}
