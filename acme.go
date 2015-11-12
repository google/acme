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

// Package goacme provides an ACME client implementation.
// See https://tools.ietf.org/html/draft-barnes-acme-04 spec for details.
package goacme

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// CertSource can obtain new certificates.
type CertSource interface {
	// Cert obtains a new certificate from the CA.
	Cert(*x509.CertificateRequest) ([]byte, error)
}

// Endpoint is ACME server directory.
type Endpoint struct {
	RegURL    string `json:"new-reg"`
	AuthzURL  string `json:"new-authz"`
	CertURL   string `json:"new-cert"`
	RevokeURL string `json:"revoke-cert"`
}

// Config is the client config. It can be used to perform initial registration
// and obtain a CertSource.
// Endpoint, Client and Key must be provided.
type Config struct {
	Key      *rsa.PrivateKey
	Contact  []string
	Endpoint Endpoint
	RegURI   string
	TermsURI string
}

// CertSource creates new CertSource using parameters in config c.
func (c *Config) CertSource() CertSource {
	// not implemented
	return nil
}

// Register create a new registration by following the "new-reg" flow,
// using provided config. The config must have non-nil Key field
// and RegURL endpoint.
//
// Config fields will be updated with the server response.
// TODO: describe what gets updated.
//
// If client argument is nil, DefaultClient will be used.
func Register(client *http.Client, config *Config) error {
	if client == nil {
		client = http.DefaultClient
	}
	nonce, err := fetchNonce(client, config.Endpoint.RegURL)
	if err != nil {
		return err
	}

	// prepare new-reg request
	reg := struct {
		Resource  string   `json:"resource"`
		Contact   []string `json:"contact"`
		Agreement string   `json:"agreement,omitempty"`
	}{
		Resource: "new-reg",
		Contact:  config.Contact,
	}
	if config.TermsURI != "" {
		reg.Agreement = config.TermsURI
	}
	body, err := jwsEncode(reg, config.Key, nonce)
	if err != nil {
		return err
	}

	// make the new-reg request
	req, err := http.NewRequest("POST", config.Endpoint.RegURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return responseError(res)
	}

	// update config with the response
	config.RegURI = res.Header.Get("location")
	if v := parseLinkHeader(res.Header, "next"); v != "" {
		config.Endpoint.AuthzURL = v
	}
	if v := parseLinkHeader(res.Header, "terms-of-service"); v != "" {
		config.TermsURI = v
	}
	return nil
}

// Discover creates a new Config from the directory data at the given url.
// The returned config will have only Endpoint field set.
// If client argument is nil, DefaultClient will be used.
func Discover(client *http.Client, url string) (*Config, error) {
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	var ep Endpoint
	if err := json.NewDecoder(res.Body).Decode(&ep); err != nil {
		return nil, fmt.Errorf("discover: %v", err)
	}
	return &Config{Endpoint: ep}, nil
}

func fetchNonce(client *http.Client, url string) (string, error) {
	resp, err := client.Head(url)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	enc := resp.Header.Get("replay-nonce")
	if enc == "" {
		return "", errors.New("nonce not found")
	}
	return enc, nil
}

func parseLinkHeader(h http.Header, rel string) string {
	for _, v := range h["Link"] {
		parts := strings.Split(v, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "rel=") {
				continue
			}
			if v := strings.Trim(p[4:], `"`); v == rel {
				return strings.Trim(parts[0], "<>")
			}
		}
	}
	return ""
}

// Error is an ACME error.
type Error struct {
	Code   int
	Type   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Type
	}
	return e.Detail
}

func responseError(resp *http.Response) error {
	b, _ := ioutil.ReadAll(resp.Body)
	e := &Error{Code: resp.StatusCode}
	if err := json.Unmarshal(b, e); err == nil {
		return e
	}
	e.Detail = string(b)
	if e.Detail == "" {
		e.Detail = resp.Status
	}
	return e
}
