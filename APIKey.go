package goauth

type APIKeyCredentials struct {
	CredentialsBase
	Key string
}

func(cred *APIKeyCredentials) Secret() string {
	return cred.Key
}

var _ SecretCredentials = &APIKeyCredentials{}
