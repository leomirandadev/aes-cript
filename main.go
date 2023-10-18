package main

import (
	"embed"
	"fmt"

	"github.com/leomirandadev/aes-cript/aescrypt"
)

//go:embed aes.key
var folder embed.FS

func main() {
	a := aescrypt.New(folder, "aes.key")

	encrypted := a.Encrypt("Hello Encrypt")
	fmt.Printf("encrypted : %s\n", encrypted)

	decrypted := a.Decrypt(encrypted)
	fmt.Printf("decrypted : %s\n", decrypted)
}
