package vaultlib

import (
	"errors"

	"github.com/hashicorp/vault/api"
)

func newclient(vaultaddr, namespace, token string) (*api.Client, error) {
	if vaultaddr == "" {
		return nil, errors.New("no vault address provided")
	}

	if token == "" {
		return nil, errors.New("no token provided")
	}

	client, err := api.NewClient(&api.Config{
		Address: vaultaddr,
	})
	if err != nil {
		return nil, err
	}

	client.SetToken(token)

	if namespace != "" {
		client.SetNamespace(namespace)
	}

	return client, nil
}
