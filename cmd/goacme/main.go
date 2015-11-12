package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	// TODO: replace the namespace with a real one befor publishing
	"devrel.googlesource.com/tools/goacme"
)

var (
	directory = flag.String("d", "https://acme-staging.api.letsencrypt.org/directory", "directory URL")
	keyPath   = flag.String("k", "key.pem", "RSA private key in pem format")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	key, err := readKey()
	if err != nil {
		log.Fatal(err)
	}

	config, err := goacme.Discover(nil, *directory)
	if err != nil {
		log.Fatal(err)
	}
	config.Key = key
	config.Contact = []string{"mailto:dude@example.com"}
	if err := goacme.Register(nil, config); err != nil {
		log.Fatalf("ERROR: %v", err)
	}
	fmt.Printf("%+v", config)
}

func readKey() (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		return nil, err
	}
	d, _ := pem.Decode(b)
	if d == nil {
		return nil, fmt.Errorf("no block found in %q", *keyPath)
	}
	if d.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("%q is unsupported", d.Type)
	}
	return x509.ParsePKCS1PrivateKey(d.Bytes)
}
