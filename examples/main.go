package main

import (
	"fmt"

	"github.com/alexballas/vaultlib"
)

func main() {
	text := "Encrypt me please!"

	vaultcfg := vaultlib.NewConfig()

	transitclient, err := vaultlib.NewTransitClient(vaultcfg, "my-key-test")
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
	fmt.Printf("Encrypted: %s \\ Version: %d\n", cipher, version)
	fmt.Printf("Decrypted: %s\n", dec)

	keycfg, err := transitclient.NewKeyConfig()
	check(err)

	keycfg.Exportable = true
	keycfg.AllowPlaintextBackup = true
	keycfg.DeletionAllowed = true
	keycfg.MinDecrypion = 1
	keycfg.MinEncryption = 1

	err = transitclient.Config(keycfg)
	check(err)

	err = transitclient.Trim(1)
	check(err)

	backup, err := transitclient.Backup()
	check(err)

	err = transitclient.Delete()
	check(err)

	err = transitclient.Restore(backup)
	check(err)

	//transitclient.Rotate()
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
