package goauth

type PasswordCredentials struct {
	CredentialsBase
	Password string
}

func(cred *PasswordCredentials) Secret() string {
	return cred.Password
}

var _ SecretCredentials = &PasswordCredentials{}
