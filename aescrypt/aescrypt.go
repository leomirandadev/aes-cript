package aescrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
)

type AESCryptDoer interface {
	Encrypt(stringToEncrypt string) (encryptedString string)
	Decrypt(encryptedString string) (decryptedString string)
}

func New(folder embed.FS, path string) AESCryptDoer {
	key, err := folder.ReadFile(path)
	if err != nil {
		panic(err.Error())
	}

	return impl{key: string(key)}
}

type impl struct {
	key string
}

func (i impl) Encrypt(stringToEncrypt string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(i.key)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func (i impl) Decrypt(encryptedString string) (decryptedString string) {

	key, _ := hex.DecodeString(i.key)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}
