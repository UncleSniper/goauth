package goauth

import (
	"sync"
)

type SecretType uint32

const (
	SECTY_UNKNOWN_NAME string = "unknown"
	SECTY_PASSWORD_NAME string = "Password"
	SECTY_API_KEY_NAME string = "API Key"
)

const (
	SECTY_UNKNOWN SecretType = iota
	SECTY_PASSWORD
	SECTY_API_KEY
)

var name2sectyID map[string]SecretType
var secty2name []string
var sectyLock sync.Mutex

func initSecretTypes() {
	name2sectyID = make(map[string]SecretType)
	name2sectyID[SECTY_UNKNOWN_NAME] = SECTY_UNKNOWN
	name2sectyID[SECTY_PASSWORD_NAME] = SECTY_PASSWORD
	name2sectyID[SECTY_API_KEY_NAME] = SECTY_API_KEY
	secty2name = []string {
		SECTY_UNKNOWN_NAME,
		SECTY_PASSWORD_NAME,
		SECTY_API_KEY_NAME,
	}
}

func InternSecretType(name string) SecretType {
	sectyLock.Lock()
	if name2sectyID == nil {
		initSecretTypes()
	}
	id, ok := name2sectyID[name]
	if !ok {
		id = SecretType(len(secty2name))
		name2sectyID[name] = id
		secty2name = append(secty2name, name)
	}
	sectyLock.Unlock()
	return id
}

func SecretTypeName(id SecretType) (name string, ok bool) {
	sectyLock.Lock()
	if name2sectyID == nil {
		initSecretTypes()
	}
	if id < SecretType(len(secty2name)) {
		name = secty2name[id]
		ok = true
	}
	sectyLock.Unlock()
	return
}

type SecretAuthFlags uint32

const (
	SECAUTHFL_SKIP_PASSWORD SecretAuthFlags = (1 << iota)
	SECAUTHFL_SKIP_API_KEY
	SECAUTHFL_SKIP_CALLBACK
	SECAUTHFL_SKIP_MAP
	SECAUTHFL_DISALLOW_GENERIC_PROTOCOL
	SECAUTHFL_DISALLOW_GENERIC_DOMAIN
)

type SecretAuthenticator[ContextT any] struct {
	Flags SecretAuthFlags
	PasswordAuth func(SecretAuthFlags, ContextT, *PasswordCredentials) (Principal, error)
	APIKeyAuth func(SecretAuthFlags, ContextT, *APIKeyCredentials) (Principal, error)
	Callback func(SecretAuthFlags, ContextT, Credentials) (Principal, error)
	children map[ProtoID]map[DomainID]func(SecretAuthFlags, ContextT, Credentials) (Principal, error)
}

func(auth *SecretAuthenticator[ContextT]) SetChild(
	proto ProtoID,
	domain DomainID,
	child func(SecretAuthFlags, ContextT, Credentials) (Principal, error),
) {
	if auth.children == nil {
		if child == nil {
			return
		}
		auth.children = make(map[ProtoID]map[DomainID]func(SecretAuthFlags, ContextT, Credentials) (Principal, error))
	}
	if child == nil {
		byProto, ok := auth.children[proto]
		if !ok {
			return
		}
		delete(byProto, domain)
	} else {
		byProto, ok := auth.children[proto]
		if !ok {
			byProto = make(map[DomainID]func(SecretAuthFlags, ContextT, Credentials) (Principal, error))
			auth.children[proto] = byProto
		}
		byProto[domain] = child
	}
}

func(auth *SecretAuthenticator[ContextT]) Authenticate(
	context ContextT,
	credentials Credentials,
) (Principal, error) {
	if (auth.Flags & SECAUTHFL_SKIP_PASSWORD) == 0 && auth.PasswordAuth != nil {
		pwd, ok := credentials.(*PasswordCredentials)
		if ok {
			return auth.PasswordAuth(auth.Flags, context, pwd)
		}
	}
	if (auth.Flags & SECAUTHFL_SKIP_API_KEY) == 0 && auth.APIKeyAuth != nil {
		api, ok := credentials.(*APIKeyCredentials)
		if ok {
			return auth.APIKeyAuth(auth.Flags, context, api)
		}
	}
	if (auth.Flags & SECAUTHFL_SKIP_CALLBACK) == 0 && auth.Callback != nil {
		prin, err := auth.Callback(auth.Flags, context, credentials)
		if prin != nil || err != nil {
			return prin, err
		}
	}
	if (auth.Flags & SECAUTHFL_SKIP_MAP) != 0 {
		return nil, nil
	}
	var child func(SecretAuthFlags, ContextT, Credentials) (Principal, error)
	if auth.children != nil && credentials != nil {
		proto := credentials.Protocol()
		if proto != UNKNOWN_PROTO_ID {
			byProto, ok := auth.children[proto]
			if !ok && (auth.Flags & SECAUTHFL_DISALLOW_GENERIC_PROTOCOL) == 0 {
				byProto, ok = auth.children[UNKNOWN_PROTO_ID]
			}
			if ok && byProto != nil {
				domain := credentials.Domain()
				if domain != NOWHERE_DOMAIN_ID {
					child, ok = byProto[domain]
					if !ok && (auth.Flags & SECAUTHFL_DISALLOW_GENERIC_DOMAIN) == 0 {
						child, ok = byProto[NOWHERE_DOMAIN_ID]
					}
					if !ok {
						child = nil
					}
				}
			}
		}
	}
	if child == nil {
		return nil, &UnmappedAuthenticatorError {
			Protocol: credentials.Protocol(),
			Domain: credentials.Domain(),
		}
	}
	return child(auth.Flags, context, credentials)
}
