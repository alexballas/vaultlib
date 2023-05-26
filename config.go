package vaultlib

type config struct {
	Address   string
	Token     string
	NameSpace string
	Key       string
}

type ConfOptions func(*config)

func newConfig() *config {
	return &config{}
}

func WithToken(t string) ConfOptions {
	return func(c *config) {
		c.Token = t
	}
}

func WithAddress(a string) ConfOptions {
	return func(c *config) {
		c.Address = a
	}
}

func WithNameSpace(n string) ConfOptions {
	return func(c *config) {
		c.Address = n
	}
}

func WithKey(k string) ConfOptions {
	return func(c *config) {
		c.Key = k
	}
}
