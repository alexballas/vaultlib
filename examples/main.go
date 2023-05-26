package main

import (
	"context"
	"fmt"

	"github.com/alexballas/vaultlib"
)

func main() {
	text := "Example text!"

	ctx := context.Background()

	transitclient, err := vaultlib.NewTransitClient(vaultlib.WithKey("my-key"))
	check(err)

	err = transitclient.CreateKey(ctx, "")
	check(err)

	listk, err := transitclient.ListKeys(ctx)
	check(err)

	cipher, version, err := transitclient.Encrypt(ctx, 0, text)
	check(err)

	dec, err := transitclient.Decrypt(ctx, cipher)
	check(err)

	hash, err := transitclient.Hmac(ctx, "sha2-256", 0, text)
	check(err)

	fmt.Println("Hash: ", hash)

	info, err := transitclient.Read(ctx)
	check(err)
	fmt.Printf("Deletion allowed for %q: %v\n", transitclient.Key, info.DeletionAllowed)
	fmt.Printf("Encryption type for %q:  %v\n", transitclient.Key, info.Type)
	fmt.Printf("Supports Ecryption: %v, Support Decryption: %v, Supports Signing: %v\n", info.SupportsEncryption, info.SupportsDecryption, info.SupportsSigning)

	fmt.Printf("All Keys: %s\n", listk)
	fmt.Printf("Text: %s\n", text)
	fmt.Printf("Encrypted: %s \\ Version: %d\n", cipher, version)
	fmt.Printf("Decrypted: %s\n", dec)

	keycfg, err := transitclient.NewKeyConfig()
	check(err)

	keycfg.Exportable = true
	keycfg.AllowPlaintextBackup = true
	keycfg.DeletionAllowed = true
	/* keycfg.MinDecrypion = 1
	keycfg.MinEncryption = 0 */

	err = transitclient.Config(ctx, keycfg)
	check(err)

	info2, err := transitclient.Read(ctx)
	check(err)
	fmt.Println(info2.Exportable)

	out, err := transitclient.Export(ctx, vaultlib.ExportEncryptionKey, 0)
	check(err)
	fmt.Printf("Exported Encryption Key: %s\n", out)

	out2, err := transitclient.Export(ctx, vaultlib.ExportHMACKey, 0)
	check(err)
	fmt.Printf("Exported HMAC Key: %s\n", out2)
	/*
		out3, err := transitclient.Export(ctx, vaultlib.ExportSigningKey, 0)
		check(err)
		fmt.Printf("Exported Signing Key: %s\n", out3)
	*/

	/* 	err = transitclient.Trim(ctx, 1)
	   	check(err) */

	backup, err := transitclient.Backup(ctx)
	check(err)

	err = transitclient.Delete(ctx)
	check(err)

	err = transitclient.Restore(ctx, backup)
	check(err)

	/* 	transitclient.Rotate(ctx)
	 */
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
