package vaultlib

import (
	"errors"

	"github.com/hashicorp/vault/api"
)

func (c *Config) newclient() (*api.Client, error) {
	if c.Address == "" {
		return nil, errors.New("no vault address provided")
	}

	if c.Token == "" {
		return nil, errors.New("no token provided")
	}

	client, err := api.NewClient(&api.Config{
		Address: c.Address,
	})
	if err != nil {
		return nil, err
	}

	client.SetToken(c.Token)

	if c.NameSpace != "" {
		client.SetNamespace(c.NameSpace)
	}

	return client, nil
}
