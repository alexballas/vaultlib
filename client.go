package vaultlib

import "github.com/hashicorp/vault/api"

func newclient(vaultaddr, namespace, token string) (*api.Client, error) {
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
