package main

import (
	"fmt"

	"github.com/alexballas/vaultlib"
)

func main() {
	text := "Encrypt me please!"

	vaultcfg := vaultlib.NewConfig()

	transitclient, err := vaultlib.NewTransitClient(vaultcfg, "123")
	check(err)

	listk, err := transitclient.Listkeys()
	check(err)

	cipher, version, err := transitclient.Encrypt(text)
	check(err)

	dec, err := transitclient.Decrypt(cipher)
	check(err)

	//transitclient.Rotate()

	fmt.Printf("All Keys   %s\n", listk)
	fmt.Printf("Text       %s\n", text)
	fmt.Printf("Encrypted: %s \\ Version: %s\n", cipher, version)
	fmt.Printf("Decrypted: %s\n", dec)

	//fmt.Println(transitclient.Config(6, 6))
	//fmt.Println(transitclient.Trim(6))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
