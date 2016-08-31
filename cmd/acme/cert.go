// Copyright 2015 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/context"

	"github.com/google/acme"
)

var (
	cmdCert = &command{
		run:       runCert,
		UsageLine: "cert [-c config] [-d url] [-s host:port] [-k key] [-expiry dur] [-bundle=true] [-manual=false] domain [domain ...]",
		Short:     "request a new certificate",
		Long: `
Cert creates a new certificate for the given domain.
It uses http-01 challenge to complete authorization flow.

The certificate will be placed alongside key file, specified with -k argument.
If the key file does not exist, a new one will be created.
Default location for the key file is {{.ConfigDir}}/domain.key,
where domain is the actually domain name provided as the command argument.

By default the obtained certificate will also contain the CA chain.
If this is undesired, specify -bundle=false argument.

The -s argument specifies the address where to run local server
for the http-01 challenge. If not specified, 127.0.0.1:8080 will be used.

An alternative to local server challenge response may be specified as -manual,
in which case instructions are displayed on the standard output.

Default location of the config dir is
{{.ConfigDir}}.
		`,
	}

	certDisco   = defaultDiscoFlag
	certAddr    = "127.0.0.1:8080"
	certExpiry  = 365 * 12 * time.Hour
	certBundle  = true
	certManual  = false
	certKeypath string
)

func init() {
	cmdCert.flag.Var(&certDisco, "d", "")
	cmdCert.flag.StringVar(&certAddr, "s", certAddr, "")
	cmdCert.flag.DurationVar(&certExpiry, "expiry", certExpiry, "")
	cmdCert.flag.BoolVar(&certBundle, "bundle", certBundle, "")
	cmdCert.flag.BoolVar(&certManual, "manual", certManual, "")
	cmdCert.flag.StringVar(&certKeypath, "k", "", "")
}

func runCert(args []string) {
	if len(args) == 0 {
		fatalf("no domain specified")
	}
	cn := args[0]
	if certKeypath == "" {
		certKeypath = filepath.Join(configDir, cn+".key")
	}

	// get user config
	uc, err := readConfig()
	if err != nil {
		fatalf("read config: %v", err)
	}
	if uc.key == nil {
		fatalf("no key found for %s", uc.URI)
	}

	// read or generate new cert key
	certKey, err := anyKey(certKeypath, true)
	if err != nil {
		fatalf("cert key: %v", err)
	}
	// generate CSR now to fail early in case of an error
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	if len(args) > 1 {
		req.DNSNames = args
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		fatalf("csr: %v", err)
	}

	// initialize acme client and start authz flow
	// we only look for http-01 challenges at the moment
	client := &acme.Client{
		Key:          uc.key,
		DirectoryURL: string(certDisco),
	}
	for _, domain := range args {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if err := authz(ctx, client, domain); err != nil {
			fatalf("%s: %v", domain, err)
		}
		cancel()
	}

	// challenge fulfilled: get the cert
	// wait at most 30 min
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cert, curl, err := client.CreateCert(ctx, csr, certExpiry, certBundle)
	if err != nil {
		fatalf("cert: %v", err)
	}
	logf("cert url: %s", curl)
	var pemcert []byte
	for _, b := range cert {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		pemcert = append(pemcert, b...)
	}
	certPath := sameDir(certKeypath, cn+".crt")
	if err := ioutil.WriteFile(certPath, pemcert, 0644); err != nil {
		fatalf("write cert: %v", err)
	}
}

func authz(ctx context.Context, client *acme.Client, domain string) error {
	z, err := client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("no supported challenge found")
	}

	// respond to http-01 challenge
	ln, err := net.Listen("tcp", certAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %v", certAddr, err)
	}
	defer ln.Close()

	if certManual {
		// manual challenge response
		thumb, err := acme.JWKThumbprint(client.Key.Public())
		if err != nil {
			return err
		}
		tok := fmt.Sprintf("%s.%s", chal.Token, thumb)
		file, err := challengeFile(chal.Token, domain, tok)
		if err != nil {
			return err
		}

		// If ACME_CHALLENGE_DIR is not set, ask user to move challenge file manually
		if os.Getenv("ACME_CHALLENGE_DIR") == "" {
			fmt.Printf("Copy %s to ROOT/.well-known/acme-challenge/%s of %s and press enter.\n",
				file, chal.Token, domain)
			var x string
			fmt.Scanln(&x)
		}
	} else {
		// auto, via local server
		val, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		path := client.HTTP01ChallengePath(chal.Token)
		go http.Serve(ln, http01Handler(path, val))

	}

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %v", err)
	}
	_, err = client.WaitAuthorization(ctx, z.URI)
	return err
}

func challengeFile(challengeFilename, domain, content string) (string, error) {
	// If ACME_CHALLENGE_DIR is set, place the challenge into it.
	// Otherwise, create a temporary file
	var f *os.File
	var err error
	if os.Getenv("ACME_CHALLENGE_DIR") != "" {
		// Create .well-known directory
		challengeDir := filepath.Join(os.Getenv("ACME_CHALLENGE_DIR"), ".well-known/acme-challenge")
		err = os.MkdirAll(challengeDir, 0755)
		if err != nil {
			return "", err
		}

		f, err = os.Create(filepath.Join(challengeDir, challengeFilename))
	} else {
		f, err = ioutil.TempFile("", domain)
	}
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprint(f, content)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return f.Name(), err
}

func http01Handler(path, value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			log.Printf("unknown request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(value))
	})
}
