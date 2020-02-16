package main

import (
	"flag"
	"fmt"
	"github.com/maxkulish/aesop"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func main()  {

	var encrypt, decrypt, output string

	flag.StringVar(&encrypt, "e", "", "Encrypt")
	flag.StringVar(&decrypt, "d", "", "Decrypt")
	flag.StringVar(&output, "o", "", "Specify output file")

	flag.Parse()

	if encrypt == "" && decrypt == "" {
		fmt.Println("Enter path to the file you want to encrypt.\nExample:\n./aesop -e text.txt\n")
		os.Exit(1)
	}

	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	start := time.Now()

	key, err := aesop.NewEncryptionKey(password, nil)
	if err != nil {
		log.Fatal(err)
	}

	if encrypt != "" {

		destFile := fmt.Sprintf("%s.enc", encrypt)
		if output != "" {
			destFile = output
		}

		// create directory for encrypted file
		err = os.MkdirAll(filepath.Dir(destFile), 0755)
		if err != nil {
			log.Fatal(err)
		}

		err := aesop.EncryptFile(encrypt, destFile, key)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("File encrypted: %s. Spent: %s", destFile, time.Since(start).String())
	}

	if decrypt != "" {

		destFile := fmt.Sprintf("%s_decr", decrypt)
		if output != "" {
			destFile = output
		}

		// create directory for encrypted file
		err = os.MkdirAll(filepath.Dir(destFile), 0755)
		if err != nil {
			log.Fatal(err)
		}

		err := aesop.DecryptFile(decrypt, destFile, key)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("File decrypted: %s. Spent: %s", destFile, time.Since(start).String())
	}
}
