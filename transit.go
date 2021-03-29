package vaultlib

import (
	"encoding/base64"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
)

type transitclient struct {
	keyname string
	client  *api.Client
}

// Decrypt text input
func (c *transitclient) Decrypt(a string) (string, error) {
	r := c.client.NewRequest("POST", "v1/transit/decrypt/"+c.keyname)

	reqbody := map[string]string{"ciphertext": a}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	decryptreply := &struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, decryptreply); err != nil {
		return "", err
	}

	sDec, _ := base64.StdEncoding.DecodeString(decryptreply.Data.Plaintext)

	return string(sDec), nil
}

// Encrypt text input.
func (c *transitclient) Encrypt(a string) (string, int, error) {
	sEnc := base64.StdEncoding.EncodeToString([]byte(a))
	r := c.client.NewRequest("POST", "v1/transit/encrypt/"+c.keyname)

	reqbody := map[string]string{"plaintext": sEnc}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", 0, err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	encryptreply := &struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, encryptreply); err != nil {
		return "", 0, err
	}

	return encryptreply.Data.Ciphertext, encryptreply.Data.KeyVersion, nil
}

// Rotate text input.
func (c *transitclient) Rotate() error {
	r := c.client.NewRequest("POST", "v1/transit/keys/"+c.keyname+"/rotate")
	resp, err := c.client.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Rewrap cipher input
func (c *transitclient) Rewrap(a string) (string, int, error) {
	r := c.client.NewRequest("POST", "v1/transit/rewrap/"+c.keyname)

	reqbody := map[string]string{"ciphertext": a}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", 0, err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	rewrapreply := &struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, rewrapreply); err != nil {
		return "", 0, err
	}

	return rewrapreply.Data.Ciphertext, rewrapreply.Data.KeyVersion, nil
}

// Trim key
func (c *transitclient) Trim(d int) error {
	r := c.client.NewRequest("POST", "v1/transit/keys/"+c.keyname+"/trim")

	reqbody := map[string]int{"min_available_version": d}

	if err := r.SetJSONBody(reqbody); err != nil {
		return err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Config key - Minimum Decryption version - Minimum Encryption version
func (c *transitclient) Config(mindecrypion, minencryption int) error {
	r := c.client.NewRequest("POST", "v1/transit/keys/"+c.keyname+"/config")

	reqbody := map[string]int{
		"min_decryption_version": mindecrypion,
		"min_encryption_version": minencryption,
	}
	if err := r.SetJSONBody(reqbody); err != nil {
		return err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// NewTransitClient - Generate new transit client.
func NewTransitClient(addr, token, keyname, namespace string) (*transitclient, error) {
	newclient, err := newclient(addr, namespace, token)
	if err != nil {
		return nil, err
	}

	return &transitclient{
		keyname: keyname,
		client:  newclient,
	}, nil
}
