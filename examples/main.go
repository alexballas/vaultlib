package main

import (
	"fmt"
	"os"

	"github.com/alexballas/vaultlib"
)

var (
	vaultaddr = os.Getenv("VAULT_ADDR")
	token     = os.Getenv("VAULT_TOKEN")
	namespace = os.Getenv("VAULT_NAMESPACE")
)

func main() {
	text := "Encrypt me please!"

	transitclient, err := vaultlib.NewTransitClient(vaultaddr, token, "123", namespace)
	check(err)

	listk, err := transitclient.Listkeys()
	check(err)

	cipher, _, err := transitclient.Encrypt(text)
	check(err)

	dec, err := transitclient.Decrypt(cipher)
	check(err)

	//transitclient.Rotate()

	fmt.Printf("All Keys   %s\n", listk)
	fmt.Printf("Text       %s\n", text)
	fmt.Printf("Encrypted: %s\n", cipher)
	fmt.Printf("Decrypted: %s\n", dec)

	//fmt.Println(transitclient.Config(6, 6))
	//fmt.Println(transitclient.Trim(6))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
