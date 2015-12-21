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
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/google/goacme"
)

var (
	cmdCert = &command{
		run:       runCert,
		UsageLine: "cert [-c config] [-d url] [-s host:port] [-k key] [-expiry dur] [-bundle=false] domain",
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

Default location of the config dir is
{{.ConfigDir}}.
		`,
	}

	certDisco   discoAlias = defaultDisco
	certAddr               = "127.0.0.1:8080"
	certExpiry             = 365 * 12 * time.Hour
	certBundle             = true
	certKeypath string
)

func init() {
	cmdCert.flag.Var(&certDisco, "d", "")
	cmdCert.flag.StringVar(&certAddr, "s", certAddr, "")
	cmdCert.flag.DurationVar(&certExpiry, "expiry", certExpiry, "")
	cmdCert.flag.BoolVar(&certBundle, "bundle", certBundle, "")
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
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		fatalf("csr: %v", err)
	}

	// perform discovery to get the new-cert URL
	disco, err := goacme.Discover(nil, string(certDisco))
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
	ln, err := net.Listen("tcp", certAddr)
	if err != nil {
		fatalf("listen %s: %v", certAddr, err)
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
	cert, curl, err := client.CreateCert(disco.CertURL, csr, certExpiry, certBundle)
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
	certPath := sameDir(certKeypath, cn+".crt")
	if err := ioutil.WriteFile(certPath, pemcert, 0644); err != nil {
		fatalf("write cert: %v", err)
	}
}

func pollCert(url string) [][]byte {
	for {
		b, err := goacme.FetchCert(nil, url, certBundle)
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
