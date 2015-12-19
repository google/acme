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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/google/goacme"
)

var (
	cmdCert = &command{
		UsageLine: "cert [-c config] [-d url] [-s host:port] [-k key] [-expiry dur] [-bundle=false] domain",
		Short:     "request a new certificate",
		Long: `
Cert creates a new certificate for the given domain.
It uses http-01 challenge to complete authorization flow.

The -s argument specifies the address where to run local server
for the http-01 challenge. If not specified, 127.0.0.1:8080 will be used.

Default location for the config file is
%s.
		`,
	}

	certC       *string // -c flag defined in init()
	certD       = cmdCert.flag.String("d", "https://acme-staging.api.letsencrypt.org/directory", "")
	certAddr    = cmdCert.flag.String("s", "127.0.0.1:8080", "")
	certExpiry  = cmdCert.flag.Duration("expiry", 365*12*time.Hour, "")
	certBundle  = cmdCert.flag.Bool("bundle", true, "")
	certKeypath = cmdCert.flag.String("k", "", "")
)

func init() {
	p := configFile(defaultConfig)
	certC = cmdCert.flag.String("c", p, "")
	cmdCert.Long = fmt.Sprintf(cmdCert.Long, p)
	cmdCert.run = runCert
}

func runCert(args []string) {
	if len(args) == 0 {
		fatalf("no domain specified")
	}
	cn := args[0]
	if *certKeypath == "" {
		*certKeypath = filepath.Join(filepath.Dir(*certC), cn+".key")
	}

	// get user config
	uc, err := readConfig(*certC)
	if err != nil {
		fatalf("read config: %v", err)
	}
	if uc.key == nil {
		fatalf("no key found for %s", uc.URI)
	}

	// read or generate new cert key
	certKey, err := anyKey(*certKeypath, true)
	if err != nil {
		fatalf("cert key: %v", err)
	}
	// generate CSR now to fail early in case of an error
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		fatalf("csr: %v", err)
	}

	// perform discovery to get the new-cert URL
	disco, err := goacme.Discover(nil, *certD)
	if err != nil {
		fatalf("discovery: %v", err)
	}
	// initialize acme client and start authz flow
	// we only look for http-01 challenges at the moment
	client := goacme.Client{Key: uc.key}
	authz, err := client.Authorize(uc.Authz, cn)
	if err != nil {
		fatalf("authorize: %v", err)
	}
	var chal *goacme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = &c
			break
		}
	}
	if chal == nil {
		fatalf("no supported challenge found")
	}

	// respond to http-01 challenge
	ln, err := net.Listen("tcp", *certAddr)
	if err != nil {
		fatalf("listen %s: %v", *certAddr, err)
	}
	go http.Serve(ln, client.HTTP01Handler(chal.Token))
	if _, err := client.Accept(chal); err != nil {
		fatalf("accept challenge: %v", err)
	}
	for {
		a, err := client.GetAuthz(authz.URI)
		if err != nil {
			errorf("authz %q: %v\n", authz.URI, err)
		}
		if a.Status == goacme.StatusInvalid {
			fatalf("could not get certificate for %s", cn)
		}
		if a.Status != goacme.StatusValid {
			// TODO: use Retry-After
			time.Sleep(time.Duration(3) * time.Second)
			continue
		}
		break
	}
	ln.Close()

	// challenge fulfilled: get the cert
	cert, curl, err := client.CreateCert(disco.CertURL, csr, *certExpiry, *certBundle)
	if err != nil {
		fatalf("cert: %v", err)
	}
	if cert == nil {
		cert = pollCert(curl)
	}
	var pemcert []byte
	for _, b := range cert {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		pemcert = append(pemcert, b...)
	}
	certPath := filepath.Join(filepath.Dir(*certKeypath), cn+".crt")
	if err := ioutil.WriteFile(certPath, pemcert, 0644); err != nil {
		fatalf("write cert: %v", err)
	}
}

func pollCert(url string) [][]byte {
	for {
		b, err := goacme.FetchCert(nil, url, *certBundle)
		if err == nil {
			return b
		}
		d := 3 * time.Second
		if re, ok := err.(goacme.RetryError); ok {
			d = time.Duration(re)
		}
		time.Sleep(d)
	}
}
