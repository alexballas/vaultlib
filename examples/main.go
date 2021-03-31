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

	info, err := transitclient.Read()
	check(err)

	fmt.Printf("Deletion allowed for %q: %v\n", transitclient.Key, info.Data["deletion_allowed"].(bool))

	//transitclient.Rotate()

	fmt.Printf("All Keys: %s\n", listk)
	fmt.Printf("Text: %s\n", text)
	fmt.Printf("Encrypted: %s \\ Version: %s\n", cipher, version)
	fmt.Printf("Decrypted: %s\n", dec)

	fmt.Println(transitclient.Config(1, 1, true, true, true))
	//transitclient.Trim(1)

	backup, err := transitclient.Backup()
	check(err)
	fmt.Println(backup)

	err = transitclient.Delete()
	check(err)

	err = transitclient.Restore(backup)
	check(err)

}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
