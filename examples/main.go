package main

import (
	"fmt"

	"github.com/alexballas/vaultlib"
)

func main() {
	text := "Encrypt me please!"

	vaultcfg := vaultlib.NewConfig()

	transitclient, err := vaultlib.NewTransitClient(vaultcfg, "my-key123")
	check(err)

	listk, err := transitclient.ListKeys()
	check(err)

	cipher, version, err := transitclient.Encrypt(text)
	check(err)

	dec, err := transitclient.Decrypt(cipher)
	check(err)

	info, err := transitclient.Read()
	check(err)

	fmt.Printf("Deletion allowed for %q: %v\n", transitclient.Key, info.DeletionAllowed)
	fmt.Printf("Encryption type for %q:  %v\n", transitclient.Key, info.Type)

	fmt.Printf("All Keys: %s\n", listk)
	fmt.Printf("Text: %s\n", text)
	fmt.Printf("Encrypted: %s \\ Version: %s\n", cipher, version)
	fmt.Printf("Decrypted: %s\n", dec)

	keycfg, err := transitclient.NewKeyConfig()
	check(err)

	keycfg.Exportable = true
	keycfg.AllowPlaintextBackup = true
	keycfg.DeletionAllowed = true

	err = transitclient.Config(keycfg)
	check(err)

	//transitclient.Trim(1)

	backup, err := transitclient.Backup()
	check(err)

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
