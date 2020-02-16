package aesop

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestEncryptDecryptRandomKey(t *testing.T) {

	t.Helper()

	f := func(text string) {

		clearText := []byte(text)

		key := NewRandomEncryptionKey()
		encrypt, err := Encrypt(clearText, key)
		if err != nil {
			log.Fatal(err)
		}

		if bytes.Equal(encrypt, clearText) {
			t.Fatalf("encrypted and unencrypted text are equal. Input: %s; encrypted: %x", text, encrypt)
		}

		decrypt, err := Decrypt(encrypt, key)

		if !bytes.Equal(decrypt, clearText) {
			t.Fatalf("encrypted and input text are not equal. Input: %s; decrypted: %s", text, string(decrypt))
		}
	}

	f("Some secret text")
	f("The quick brown fox jumps over the lazy dog.")
}

func TestEncryptDecryptPassword(t *testing.T) {

	t.Helper()

	f := func(text, password string) {

		inputText := []byte(text)

		key, err := NewEncryptionKey([]byte(password), nil)
		encrypt, err := Encrypt(inputText, key)
		if err != nil {
			log.Fatal(err)
		}

		if bytes.Equal(encrypt, inputText) {
			t.Fatalf("encrypted and unencrypted text are equal. Input: %s; encrypted: %x", text, encrypt)
		}

		decrypt, err := Decrypt(encrypt, key)

		if !bytes.Equal(decrypt, inputText) {
			t.Fatalf("encrypted and input text are not equal. Input: %s; decrypted: %s", text, string(decrypt))
		}
	}

	f("Some secret text", "L0ngStrongPassword")
	f("The quick brown fox jumps over the lazy dog.", "@W3tT4UGTjsp6ZjcwR-e-K9Fvf")
}

func BenchmarkNewRandomEncryptionKey(b *testing.B) {

	randKey := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, randKey[:])
	if err != nil {
		b.Fatal(err)
	}

	data, err := ioutil.ReadFile("./testdata/big")
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(data, randKey)
	}
}

func TestEncryptDecryptFile(t *testing.T) {

	t.Helper()

	f := func(filename, expRes string ) {

		key := NewRandomEncryptionKey()

		encrFile := fmt.Sprintf("%s.enc", filename)
		err := EncryptFile(filename, encrFile, key)
		if err != nil {
			t.Fatal(err)
		}

		newDecrFile := encrFile+"_new"
		err = DecryptFile(encrFile, newDecrFile, key)
		if err != nil {
			log.Fatal(err)
		}

		readFile, err := ioutil.ReadFile(newDecrFile)
		if !bytes.Equal([]byte(expRes), readFile) {
			t.Fatalf("decrypted file and original files are different. Original %s; decrypted %s", filename, newDecrFile)
		}

		_ = os.Remove(newDecrFile)
		_ = os.Remove(encrFile)

	}

	f("./testdata/text.txt", "Utility for encrypting and decrypting files with AES-256 GCM and Scrypt")
}
