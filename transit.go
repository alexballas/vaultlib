package vaultlib

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/mitchellh/mapstructure"
)

type Transit struct {
	Key    string
	client *api.Client
}

type KeyInfo struct {
	Type                 string `mapstructure:"type"`
	DeletionAllowed      bool   `mapstructure:"deletion_allowed"`
	Derived              bool   `mapstructure:"derived"`
	Exportable           bool   `mapstructure:"exportable"`
	AllowPlaintextBackup bool   `mapstructure:"allow_plaintext_backup"`
	Keys                 struct {
		Num1 int `mapstructure:"1"`
	} `mapstructure:"keys"`
	MinDecryptionVersion int    `mapstructure:"min_decryption_version"`
	MinEncryptionVersion int    `mapstructure:"min_encryption_version"`
	Name                 string `mapstructure:"name"`
	SupportsEncryption   bool   `mapstructure:"supports_encryption"`
	SupportsDecryption   bool   `mapstructure:"supports_decryption"`
	SupportsDerivation   bool   `mapstructure:"supports_derivation"`
	SupportsSigning      bool   `mapstructure:"supports_signing"`
}

type KeyConfig struct {
	MinDecrypion         int
	MinEncryption        int
	DeletionAllowed      bool
	Exportable           bool
	AllowPlaintextBackup bool
}

// Decrypt the provided ciphertext using the named key.
// https://www.vaultproject.io/api/secret/transit#decrypt-data
func (c *Transit) Decrypt(a string) (text string, err error) {
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

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", err
	}
	sDec, _ := base64.StdEncoding.DecodeString(reply.Data["plaintext"].(string))

	return string(sDec), nil
}

// Encrypt the provided plaintext using the named key.
// https://www.vaultproject.io/api/secret/transit#encrypt-data
func (c *Transit) Encrypt(a string) (cipher string, version json.Number, err error) {
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

	reply := &api.Secret{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", "", err
	}

	return reply.Data["ciphertext"].(string), reply.Data["key_version"].(json.Number), nil
}

// Rotate the version of the named key.
// After rotation, new plaintext requests will be  encrypted with the
// new version of the key.
// https://www.vaultproject.io/api/secret/transit#rotate-key
func (c *Transit) Rotate() (err error) {
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

// Rewrap  the provided ciphertext using the latest version of the named key.
// Because this never returns plaintext, it is possible to delegate this
// functionality to untrusted users or scripts..
// https://www.vaultproject.io/api/secret/transit#rewrap-data
func (c *Transit) Rewrap(a string) (cipher string, version json.Number, err error) {
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

	reply := &api.Secret{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", "", err
	}

	return reply.Data["ciphertext"].(string), reply.Data["key_version"].(json.Number), nil
}

// Trim older key versions setting a minimum version for the keyring.
// Once trimmed, previous versions of the key cannot be recovered.
// https://www.vaultproject.io/api/secret/transit#trim-key
func (c *Transit) Trim(d int) (err error) {
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

// ListKeys returns a list of keys. Only the key names are returned
// (not the actual keys themselves).
// https://www.vaultproject.io/api/secret/transit#list-keys
func (c *Transit) ListKeys() (keys []interface{}, err error) {
	r := c.client.NewRequest("LIST", "/v1/transit/keys")

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return nil, err
	}

	return reply.Data["keys"].([]interface{}), nil
}

// Config key - Allows tuning configuration values for a given key.
// https://www.vaultproject.io/api/secret/transit#update-key-configuration
func (c *Transit) Config(keycfg *KeyConfig) (err error) {
	if c.Key == "" {
		return errors.New("no key provided")
	}

	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key+"/config")

	reqbody := map[string]interface{}{
		"min_decryption_version": keycfg.MinDecrypion,
		"min_encryption_version": keycfg.MinEncryption,
		"deletion_allowed":       keycfg.DeletionAllowed,
		"exportable":             keycfg.Exportable,
		"allow_plaintext_backup": keycfg.AllowPlaintextBackup,
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

// Backup returns a plaintext backup of a named key.
// The backup contains all the configuration data and keys of all
// the versions along with the HMAC key.
// https://www.vaultproject.io/api/secret/transit#backup-key
func (c *Transit) Backup() (backup string, err error) {
	if c.Key == "" {
		return "", errors.New("no key provided")
	}

	r := c.client.NewRequest("GET", "/v1/transit/backup/"+c.Key)

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", err
	}

	return reply.Data["backup"].(string), nil
}

// Restore the backup as a named key. This will restore the key
// configurations and all the versions of the named key along with HMAC keys.
func (c *Transit) Restore(backup string) (err error) {
	if c.Key == "" {
		return errors.New("no key provided")
	}

	r := c.client.NewRequest("POST", "/v1/transit/restore/"+c.Key)

	reqbody := map[string]string{"backup": backup}
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

// Read returns information about a named encryption key.
// https://www.vaultproject.io/api/secret/transit#read-key
func (c *Transit) Read() (key *KeyInfo, err error) {
	if c.Key == "" {
		return nil, errors.New("no key provided")
	}

	r := c.client.NewRequest("GET", "/v1/transit/keys/"+c.Key)

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return nil, err
	}
	out := &KeyInfo{}
	mapstructure.Decode(reply.Data, out)

	return out, nil
}

// Delete a named encryption key. It will no longer be possible
// to decrypt any data encrypted with the named key.
// https://www.vaultproject.io/api/secret/transit#delete-key
func (c *Transit) Delete() (err error) {
	if c.Key == "" {
		return errors.New("no key provided")
	}

	r := c.client.NewRequest("DELETE", "/v1/transit/keys/"+c.Key)

	resp, err := c.client.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// NewTransitClient - Generate new transit client.
func NewTransitClient(c *Config, key string) (*Transit, error) {
	newclient, err := c.newclient()
	if err != nil {
		return nil, err
	}

	return &Transit{
		Key:    key,
		client: newclient,
	}, nil
}

// NewKeyConfig - Generate new key configuration.
func (c *Transit) NewKeyConfig() (*KeyConfig, error) {
	if c.Key == "" {
		return nil, errors.New("no key provided")
	}

	return &KeyConfig{
		MinDecrypion:         1,
		MinEncryption:        0,
		DeletionAllowed:      false,
		Exportable:           false,
		AllowPlaintextBackup: false,
	}, nil
}
