package vaultlib

import "os"

type Config struct {
	Address   string
	Token     string
	NameSpace string
}

func NewConfig() *Config {
	var cfg Config

	if v := os.Getenv("VAULT_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("VAULT_ADDR"); v != "" {
		cfg.Address = v
	}
	if v := os.Getenv("VAULT_NAMESPACE"); v != "" {
		cfg.NameSpace = v
	}

	return &cfg
}
