package vaultlib

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/mitchellh/mapstructure"
)

const (
	ExportEncryptionKey ExportKeyType = iota
	ExportSigningKey
	ExportHMACKey
)

type ExportKeyType int

var (
	ErrNoKey         = errors.New("no key provided")
	ErrBadAlgo       = errors.New("invalid algorith input")
	ErrBadKey        = errors.New("invalid key type")
	ErrBadKeyVersion = errors.New("bad key version")
)

type Transit struct {
	client *api.Client
	Key    string
}

type KeyInfo struct {
	Keys struct {
		Num1 interface{} `mapstructure:"1"`
	} `mapstructure:"keys"`
	Name                 string `mapstructure:"name"`
	Type                 string `mapstructure:"type"`
	MinEncryptionVersion int64  `mapstructure:"min_encryption_version"`
	MinDecryptionVersion int64  `mapstructure:"min_decryption_version"`
	Exportable           bool   `mapstructure:"exportable"`
	AllowPlaintextBackup bool   `mapstructure:"allow_plaintext_backup"`
	Derived              bool   `mapstructure:"derived"`
	DeletionAllowed      bool   `mapstructure:"deletion_allowed"`
	SupportsEncryption   bool   `mapstructure:"supports_encryption"`
	SupportsDecryption   bool   `mapstructure:"supports_decryption"`
	SupportsDerivation   bool   `mapstructure:"supports_derivation"`
	SupportsSigning      bool   `mapstructure:"supports_signing"`
}

type KeyConfig struct {
	MinDecrypion         int64
	MinEncryption        int64
	DeletionAllowed      bool
	Exportable           bool
	AllowPlaintextBackup bool
}

// Decrypt the provided ciphertext using the named key.
// https://www.vaultproject.io/api-docs/secret/transit#decrypt-data
func (c *Transit) Decrypt(ctx context.Context, input string) (text string, err error) {
	if c.Key == "" {
		return "", ErrNoKey
	}

	r := c.client.NewRequest("POST", "/v1/transit/decrypt/"+c.Key)

	reqbody := map[string]string{"ciphertext": input}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
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
// https://www.vaultproject.io/api-docs/secret/transit#encrypt-data
func (c *Transit) Encrypt(ctx context.Context, key_version int, input string) (cipher string, version int64, err error) {
	if c.Key == "" {
		return "", 0, ErrNoKey
	}

	sEnc := base64.StdEncoding.EncodeToString([]byte(input))
	r := c.client.NewRequest("POST", "/v1/transit/encrypt/"+c.Key)

	reqbody := map[string]string{
		"plaintext":   sEnc,
		"key_version": strconv.Itoa(key_version),
	}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", 0, err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", 0, err
	}

	version, err = reply.Data["key_version"].(json.Number).Int64()
	if err != nil {
		return "", 0, err
	}

	return reply.Data["ciphertext"].(string), version, nil
}

// Rotate the version of the named key.
// After rotation, new plaintext requests will be  encrypted with the
// new version of the key.
// https://www.vaultproject.io/api-docs/secret/transit#rotate-key
func (c *Transit) Rotate(ctx context.Context) (err error) {
	if c.Key == "" {
		return ErrNoKey
	}

	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key+"/rotate")
	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}

	return nil
}

// Rewrap  the provided ciphertext using the latest version of the named key.
// Because this never returns plaintext, it is possible to delegate this
// functionality to untrusted users or scripts..
// https://www.vaultproject.io/api-docs/secret/transit#rewrap-data
func (c *Transit) Rewrap(ctx context.Context, input string) (cipher string, version int64, err error) {
	if c.Key == "" {
		return "", 0, ErrNoKey
	}

	r := c.client.NewRequest("POST", "/v1/transit/rewrap/"+c.Key)

	reqbody := map[string]string{"ciphertext": input}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", 0, err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}

	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", 0, err
	}

	version, err = reply.Data["key_version"].(json.Number).Int64()
	if err != nil {
		return "", 0, err
	}

	return reply.Data["ciphertext"].(string), version, nil
}

// Trim older key versions setting a minimum version for the keyring.
// Once trimmed, previous versions of the key cannot be recovered.
// https://www.vaultproject.io/api-docs/secret/transit#trim-key
func (c *Transit) Trim(ctx context.Context, d int64) (err error) {
	if c.Key == "" {
		return ErrNoKey
	}

	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key+"/trim")

	reqbody := map[string]int64{"min_available_version": d}

	if err := r.SetJSONBody(reqbody); err != nil {
		return err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}

	return nil
}

// ListKeys returns a list of keys. Only the key names are returned
// (not the actual keys themselves).
// https://www.vaultproject.io/api-docs/secret/transit#list-keys
func (c *Transit) ListKeys(ctx context.Context) (keys []interface{}, err error) {
	r := c.client.NewRequest("LIST", "/v1/transit/keys")

	resp, err := c.client.RawRequestWithContext(ctx, r)
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
// https://www.vaultproject.io/api-docs/secret/transit#update-key-configuration
func (c *Transit) Config(ctx context.Context, keycfg *KeyConfig) (err error) {
	if c.Key == "" {
		return ErrNoKey
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

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}

	return nil
}

// Backup returns a plaintext backup of a named key.
// The backup contains all the configuration data and keys of all
// the versions along with the HMAC key.
// https://www.vaultproject.io/api-docs/secret/transit#backup-key
func (c *Transit) Backup(ctx context.Context) (backup string, err error) {
	if c.Key == "" {
		return "", ErrNoKey
	}

	r := c.client.NewRequest("GET", "/v1/transit/backup/"+c.Key)

	resp, err := c.client.RawRequestWithContext(ctx, r)
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
func (c *Transit) Restore(ctx context.Context, backup string) (err error) {
	if c.Key == "" {
		return ErrNoKey
	}

	r := c.client.NewRequest("POST", "/v1/transit/restore/"+c.Key)

	reqbody := map[string]string{"backup": backup}
	if err := r.SetJSONBody(reqbody); err != nil {
		return err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}

	return nil
}

// Read returns information about a named encryption key.
// https://www.vaultproject.io/api-docs/secret/transit#read-key
func (c *Transit) Read(ctx context.Context) (key *KeyInfo, err error) {
	if c.Key == "" {
		return nil, ErrNoKey
	}

	r := c.client.NewRequest("GET", "/v1/transit/keys/"+c.Key)

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return nil, err
	}

	out := &KeyInfo{}
	if err := mapstructure.Decode(reply.Data, out); err != nil {
		return nil, err
	}

	return out, nil
}

// Delete a named encryption key. It will no longer be possible
// to decrypt any data encrypted with the named key.
// https://www.vaultproject.io/api-docs/secret/transit#delete-key
func (c *Transit) Delete(ctx context.Context) (err error) {
	if c.Key == "" {
		return ErrNoKey
	}

	r := c.client.NewRequest("DELETE", "/v1/transit/keys/"+c.Key)

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}

	return nil
}

// Hmac - Geneate HMAC
// https://www.vaultproject.io/api-docs/secret/transit#generate-hmac
func (c *Transit) Hmac(ctx context.Context, algo string, key_version int, input string) (text string, err error) {
	if c.Key == "" {
		return "", ErrNoKey
	}

	algoExists := func() bool {
		supportedAlgos := [...]string{
			"sha1",
			"sha2-224",
			"sha2-256",
			"sha2-384",
			"sha2-512",
			"sha3-224",
			"sha3-256",
			"sha3-384",
			"sha3-512",
		}

		for _, a := range supportedAlgos {
			if a == algo {
				return true
			}
		}
		return false
	}

	if !algoExists() {
		return "", ErrBadAlgo
	}

	inputB64 := base64.StdEncoding.EncodeToString([]byte(input))

	r := c.client.NewRequest("POST", "/v1/transit/hmac/"+c.Key+"/"+algo)

	reqbody := map[string]string{"input": inputB64, "key_version": strconv.Itoa(key_version)}

	if err := r.SetJSONBody(reqbody); err != nil {
		return "", err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", err
	}
	hmacRes := reply.Data["hmac"].(string)

	return hmacRes, nil
}

// Create - Create new key.
// https://www.vaultproject.io/api-docs/secret/transit#create-key
func (c *Transit) CreateKey(ctx context.Context, keytype string) error {
	r := c.client.NewRequest("POST", "/v1/transit/keys/"+c.Key)

	keyExists := func() bool {
		if keytype == "" {
			return true
		}

		supportedKeys := [...]string{
			"aes128-gcm96",
			"aes256-gcm96",
			"chacha20-poly1305",
			"ed25519",
			"ecdsa-p256",
			"ecdsa-p384",
			"ecdsa-p521",
			"rsa-2048",
			"rsa-3072",
			"rsa-4096",
			"hmac",
		}

		for _, a := range supportedKeys {
			if a == keytype {
				return true
			}
		}
		return false
	}

	if !keyExists() {
		return ErrBadKey
	}

	reqbody := map[string]interface{}{}

	if keytype != "" {
		reqbody = map[string]interface{}{"type": keytype}
	}

	if err := r.SetJSONBody(reqbody); err != nil {
		return err
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}

	return nil
}

// Export key.
// https://www.vaultproject.io/api-docs/secret/transit#export-key
func (c *Transit) Export(ctx context.Context, key_type ExportKeyType, key_version int) (string, error) {
	if c.Key == "" {
		return "", ErrNoKey
	}

	var ktype string
	switch key_type {
	case ExportEncryptionKey:
		ktype = "encryption-key"
	case ExportSigningKey:
		ktype = "signing-key"
	case ExportHMACKey:
		ktype = "hmac-key"
	default:
		return "", ErrBadKey
	}

	if key_version < 0 {
		return "", ErrBadKeyVersion
	}

	r := c.client.NewRequest("GET", "/v1/transit/export/"+ktype+"/"+c.Key)

	if key_version > 0 {
		r = c.client.NewRequest("GET", "/v1/transit/export/"+ktype+"/"+c.Key+"/"+strconv.Itoa(key_version))
	}

	resp, err := c.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	reply := &api.Secret{}
	if err := jsonutil.DecodeJSONFromReader(resp.Body, reply); err != nil {
		return "", err
	}

	out := &KeyInfo{}
	if err := mapstructure.Decode(reply.Data, out); err != nil {
		return "", err
	}

	return out.Keys.Num1.(string), nil
}

// NewTransitClient - Generate new transit client.
func NewTransitClient(opts ...ConfOptions) (*Transit, error) {
	c := newConfig()
	for _, o := range opts {
		o(c)
	}

	if c.Token == "" {
		c.Token = os.Getenv("VAULT_TOKEN")
	}

	if c.Address == "" {
		c.Address = os.Getenv("VAULT_ADDR")
	}

	if c.NameSpace == "" {
		c.NameSpace = os.Getenv("VAULT_NAMESPACE")
	}

	if c.Key == "" {
		return nil, ErrNoKey
	}

	newclient, err := c.newclient()
	if err != nil {
		return nil, err
	}

	return &Transit{
		Key:    c.Key,
		client: newclient,
	}, nil
}

// NewKeyConfig - Generate new key configuration.
func (c *Transit) NewKeyConfig() (*KeyConfig, error) {
	if c.Key == "" {
		return nil, ErrNoKey
	}

	return &KeyConfig{
		MinDecrypion:         1,
		MinEncryption:        0,
		DeletionAllowed:      false,
		Exportable:           false,
		AllowPlaintextBackup: false,
	}, nil
}
