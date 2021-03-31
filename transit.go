package vaultlib

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
)

type transitclient struct {
	Key    string
	client *api.Client
}

// Decrypt text input.
func (c *transitclient) Decrypt(a string) (cipher string, err error) {
	if c.Key == "" {
		return "", errors.New("no key provided")
	}

	r := c.client.NewRequest("POST", "/v1/transit/decrypt/"+c.Key)

	reqbody := map[string]string{"ciphertext": a}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	decryptreply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, decryptreply); err != nil {
		return "", err
	}
	sDec, _ := base64.StdEncoding.DecodeString(decryptreply.Data["plaintext"].(string))

	return string(sDec), nil
}

// Encrypt text input.
func (c *transitclient) Encrypt(a string) (text string, version json.Number, err error) {
	if c.Key == "" {
		return "", "", errors.New("no key provided")
	}

	sEnc := base64.StdEncoding.EncodeToString([]byte(a))
	r := c.client.NewRequest("POST", "/v1/transit/encrypt/"+c.Key)

	reqbody := map[string]string{"plaintext": sEnc}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", "", err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	encreply := &api.Secret{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, encreply); err != nil {
		return "", "", err
	}

	return encreply.Data["ciphertext"].(string), encreply.Data["key_version"].(json.Number), nil
}

// Rotate key.
func (c *transitclient) Rotate() (err error) {
	if c.Key == "" {
		return errors.New("no key provided")
	}

	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key+"/rotate")
	resp, err := c.client.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Rewrap cipher input.
func (c *transitclient) Rewrap(a string) (cipher string, version json.Number, err error) {
	if c.Key == "" {
		return "", "", errors.New("no key provided")
	}

	r := c.client.NewRequest("POST", "/v1/transit/rewrap/"+c.Key)

	reqbody := map[string]string{"ciphertext": a}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", "", err
	}

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	rewrapreply := &api.Secret{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, rewrapreply); err != nil {
		return "", "", err
	}

	return rewrapreply.Data["ciphertext"].(string), rewrapreply.Data["key_version"].(json.Number), nil
}

// Trim key.
func (c *transitclient) Trim(d int) (err error) {
	if c.Key == "" {
		return errors.New("no key provided")
	}

	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key+"/trim")

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

// Listkeys
func (c *transitclient) Listkeys() (keys []interface{}, err error) {
	r := c.client.NewRequest("LIST", "/v1/transit/keys")

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	listreply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, listreply); err != nil {
		return nil, err
	}

	return listreply.Data["keys"].([]interface{}), nil
}

// Config key - Minimum Decryption version - Minimum Encryption version.
func (c *transitclient) Config(mindecrypion, minencryption int) (err error) {
	if c.Key == "" {
		return errors.New("no key provided")
	}
	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key+"/config")

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

// Newtransitclient - Generate new transit client.
func NewTransitClient(c *Config, key string) (*transitclient, error) {
	newclient, err := c.newclient()
	if err != nil {
		return nil, err
	}

	return &transitclient{
		Key:    key,
		client: newclient,
	}, nil
}
