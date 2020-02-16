package aesop

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
)

// NewRandomEncryptionKey generates a random 256-bit key
// for Encrypt() and Decrypt() functions
func NewRandomEncryptionKey() *[32]byte {

	// AES-256 needs 32-byte key
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		log.Fatal("encryption key error", err)
	}

	return &key
}

func NewEncryptionKey(password, salt []byte) (*[32]byte, error) {

	if len(password) <= 10 {
		return nil, errors.New("password to short")
	}

	if len(salt) == 0 {
		salt = password[:12]
		password = password[12:]
	}

	dk, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}

	var key [32]byte
	copy(key[:], dk)

	return &key, nil

}

// Encrypt encrypts data using AES-GCM 256-bit.
func Encrypt(text []byte, key *[32]byte) ([]byte, error)  {

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, text, nil), nil
}

func EncryptFile(filename, destfile string, key *[32]byte) error  {

	f, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("can't read file %s. Error: %+v", filename, err)
	}

	cipherText, err := Encrypt(f, key)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(destfile, cipherText, 0744)
	if err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}

// Decrypt decrypts data using 256-bit AES-GCM
func Decrypt(ciphertext []byte, key *[32]byte) ([]byte, error)  {

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(
		nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
		)
}

func DecryptFile(encFile, decrFile string, key *[32]byte) error  {

	file, err := ioutil.ReadFile(encFile)
	if err != nil {
		log.Fatal(err)
	}

	decrypt, err := Decrypt(file, key)
	if err != nil {
		log.Fatal(err)
		return err
	}

	return ioutil.WriteFile(decrFile, decrypt, 0744)
}