package vaultlib

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
)

type transitclient struct {
	vaultaddr string
	token     string
	keyname   string
	namespace string
}

// Decrypt text input
func (c *transitclient) Decrypt(a string) (string, error) {
	jsonin := &struct {
		Ciphertext string `json:"ciphertext"`
	}{
		Ciphertext: a,
	}

	jsondata, err := json.Marshal(jsonin)
	if err != nil {
		return "", err
	}
	b := bytes.NewBuffer(jsondata)

	client := http.Client{}
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/decrypt/"+c.keyname, b)
	if err != nil {
		return "", err
	}
	headers := http.Header{
		"X-Vault-Token":     {c.token},
		"X-Vault-Namespace": {c.namespace},
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	decryptreply := &struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
		WrapInfo interface{} `json:"wrap_info"`
		Warnings interface{} `json:"warnings"`
		Auth     interface{} `json:"auth"`
	}{}

	err = json.Unmarshal(body, decryptreply)
	if err != nil {
		return "", err
	}
	sDec, _ := base64.StdEncoding.DecodeString(decryptreply.Data.Plaintext)

	return string(sDec), nil
}

// Encrypt text input.
func (c *transitclient) Encrypt(a string) (string, int, error) {
	sEnc := base64.StdEncoding.EncodeToString([]byte(a))
	jsonin := &struct {
		Plaintext string `json:"plaintext"`
	}{
		Plaintext: sEnc,
	}
	jsondata, err := json.Marshal(jsonin)
	if err != nil {
		return "", 0, err
	}
	b := bytes.NewBuffer(jsondata)

	client := http.Client{}
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/encrypt/"+c.keyname, b)
	if err != nil {
		return "", 0, err
	}
	headers := http.Header{
		"X-Vault-Token":     {c.token},
		"X-Vault-Namespace": {c.namespace},
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	encryptreply := &struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
		WrapInfo interface{} `json:"wrap_info"`
		Warnings interface{} `json:"warnings"`
		Auth     interface{} `json:"auth"`
	}{}

	err = json.Unmarshal(body, encryptreply)
	if err != nil {
		return "", 0, err
	}

	return encryptreply.Data.Ciphertext, encryptreply.Data.KeyVersion, nil
}

// Rotate text input.
func (c *transitclient) Rotate() error {
	client := http.Client{}
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/keys/"+c.keyname+"/rotate", nil)
	if err != nil {
		return err
	}
	headers := http.Header{
		"X-Vault-Token":     {c.token},
		"X-Vault-Namespace": {c.namespace},
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return nil
}

// Rewrap cipher input
func (c *transitclient) Rewrap(a string) (string, int, error) {
	jsonin := &struct {
		Ciphertext string `json:"ciphertext"`
	}{
		Ciphertext: a,
	}

	jsondata, err := json.Marshal(jsonin)
	if err != nil {
		return "", 0, err
	}
	b := bytes.NewBuffer(jsondata)

	client := http.Client{}
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/rewrap/"+c.keyname, b)
	if err != nil {
		return "", 0, err
	}
	headers := http.Header{
		"X-Vault-Token":     {c.token},
		"X-Vault-Namespace": {c.namespace},
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	rewrapreply := &struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
		WrapInfo interface{} `json:"wrap_info"`
		Warnings interface{} `json:"warnings"`
		Auth     interface{} `json:"auth"`
	}{}

	err = json.Unmarshal(body, rewrapreply)
	if err != nil {
		return "", 0, err
	}
	return rewrapreply.Data.Ciphertext, rewrapreply.Data.KeyVersion, nil
}

// Trim key
func (c *transitclient) Trim(d int) error {
	jsonin := &struct {
		Minversion int `json:"min_available_version"`
	}{
		Minversion: d,
	}

	jsondata, err := json.Marshal(jsonin)
	if err != nil {
		return err
	}
	b := bytes.NewBuffer(jsondata)

	client := http.Client{}
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/keys/"+c.keyname+"/trim", b)
	if err != nil {
		return err
	}
	headers := http.Header{
		"X-Vault-Token":     {c.token},
		"X-Vault-Namespace": {c.namespace},
	}
	req.Header = headers
	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
}

// Config key - Minimum Decryption version - Minimum Encryption version
func (c *transitclient) Config(mindecrypion, minencryption int) error {
	jsonin := &struct {
		MinDecryptionVersion int `json:"min_decryption_version"`
		MinEncryptionVersion int `json:"min_encryption_version"`
	}{
		MinDecryptionVersion: mindecrypion,
		MinEncryptionVersion: minencryption,
	}
	jsondata, err := json.Marshal(jsonin)
	if err != nil {
		return err
	}
	b := bytes.NewBuffer(jsondata)

	client := http.Client{}
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/keys/"+c.keyname+"/config", b)
	if err != nil {
		return err
	}
	headers := http.Header{
		"X-Vault-Token":     {c.token},
		"X-Vault-Namespace": {c.namespace},
	}
	req.Header = headers

	_, err = client.Do(req)
	if err != nil {
		return err
	}
	return nil
}

// NewTransitClient - Generate new transit client.
func NewTransitClient(addr, token, keyname, namespace string) *transitclient {
	return &transitclient{
		vaultaddr: addr,
		token:     token,
		keyname:   keyname,
		namespace: namespace,
	}
}
