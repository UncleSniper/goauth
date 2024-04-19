package goauth

type SecretCredentials interface {
	Credentials
	Secret() string
}
