package transit

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
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/decrypt/my-key", b)
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
	req, err := http.NewRequest("POST", c.vaultaddr+"v1/transit/encrypt/my-key", b)
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

// NewTransitClient - Generate new transit client.
func NewTransitClient(addr, token, namespace string) *transitclient {
	return &transitclient{
		vaultaddr: addr,
		token:     token,
		namespace: namespace,
	}
}
