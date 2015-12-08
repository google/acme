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
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
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

type Client struct {
	http.Client
	Key *rsa.PrivateKey
}

type Account struct {
	Contact        []string
	AgreedTerms    string `json:"agreement"`
	CurrentTerms   string
	URI            string
	Authorizations string
	Certificates   string
}

// Challenge encodes a returned CA challenge.
type Challenge struct {
	Type   string
	URI    string `json:"uri"`
	Token  string
	Status string
}

// ChallengeSet encodes a set of challenges, together with permitted combinations.
type ChallengeSet struct {
	Challenges   []Challenge
	Combinations [][]int
}

// AuthzIdentifier encodes an ID for something to authorize, typically a domain.
type AuthzIdentifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// Authorization encodes an authorization response.
type Authorization struct {
	Identifier AuthzIdentifier
	URI        string
	Status     string
	ChallengeSet
}

// CertSource creates new CertSource using parameters in config c.
func (c *Config) CertSource() CertSource {
	// not implemented
	return nil
}

// Auxiliary method to send registration requests.
func doReg(client *Client, url string, account *Account, resource string, update bool) (*Account, error) {
	nonce, err := fetchNonce(client, url)
	if err != nil {
		return nil, err
	}

	// prepare registration request
	reg := struct {
		Resource  string   `json:"resource"`
		Contact   []string `json:"contact,omitempty"`
		Agreement string   `json:"agreement,omitempty"`
	}{
		Resource: resource,
	}
	if update {
		reg.Contact = account.Contact
		reg.Agreement = account.Agreement
	}
	body, err := jwsEncodeJSON(reg, config.Key, nonce)
	if err != nil {
		return nil, err
	}

	// make the registration request
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	res, err := config.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, responseError(res)
	}

	var acct Account
	if err := json.NewDecoder(res.Body).Decode(&acct); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	if v := parseLinkHeader(res.Header, "terms-of-service"); v != "" {
		acct.CurrentTerms = v
	}
	acct.URI = res.Header.Get("Location")

	// update config endpoint with the response
	if v := parseLinkHeader(res.Header, "next"); v != "" {
		config.Endpoint.AuthzURL = v
	}
	return &acct, nil
}

// Register create a new registration by following the "new-reg" flow,
// using the provided config. The config must have a non-nil Key field
// and a non-nil Endpoint.RegURL.
//
// Config fields will be updated with the server response.
// TODO: describe what gets updated.
//
// If client argument is nil, DefaultClient will be used.
func Register(client *Client, url string, account *Account) (*Account, error) {
	return doReg(config, url, account, "new-reg", true)
}

// GetReg retrieves an existing registration, using the provided config.
// The config must have non-nil Key and RegURI fields.
//
// Config fields will be updated with the server response.
// TODO: describe what gets updated.
//
// If client argument is nil, DefaultClient will be used.
func GetReg(client *Client, url string, account *Account) (*Account, error) {
	return doReg(config, url, account, "reg", false)
}

// UpdateReg retrieves an existing registration, using the provided config.
// The config must have non-nil Key and RegURI fields.
//
// Config fields will be updated with the server response.
// TODO: describe what gets updated.
//
// If client argument is nil, DefaultClient will be used.
func UpdateReg(client *Client, url string, account *Account) (*Account, error) {
	return doReg(config, url, account, "reg", true)
}

// authorize performs the initial step in an authorization flow.
// The server will either respond with an error or with a list of challenges
// which the client will have to choose from and perform, to complete authorization.
//
// If client argument is nil, DefaultClient will be used.
func authorize(client *Client, domain string) (*Authorization, error) {
	if client == nil {
		client = http.DefaultClient
	}
	nonce, err := fetchNonce(client, config.Endpoint.AuthzURL)
	if err != nil {
		return nil, err
	}

	// prepare new-authz request
	req := struct {
		Resource   string          `json:"resource"`
		Identifier AuthzIdentifier `json:"identifier"`
	}{
		Resource:   "new-authz",
		Identifier: AuthzIdentifier{Type: "dns", Value: domain},
	}
	body, err := jwsEncodeJSON(req, config.Key, nonce)
	if err != nil {
		return nil, err
	}

	// make the new-authz request
	res, err := client.Post(config.Endpoint.AuthzURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, responseError(res)
	}

	authzresp := Authorization{}
	if err := json.NewDecoder(res.Body).Decode(&authzresp); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}

	authzresp.URI = res.Header.Get("Location")

	if authzresp.Status != "pending" {
		return nil, fmt.Errorf("Unexpected status: %s", authzresp.Status)
	}
	return &authzresp, nil
}

// acceptChallenge informs the server that the client accepts one of its challenges for validation.
// The server will then perform the validation asynchronously.
//
// If client argument is nil, DefaultClient will be used.
func acceptChallenge(client *Client, challenge Challenge) (Challenge, error) {
	if client == nil {
		client = http.DefaultClient
	}
	nonce, err := fetchNonce(client, challenge.URI)
	if err != nil {
		return Challenge{}, err
	}

	// prepare challenge request
	req := struct {
		Resource string `json:"resource"`
		Type     string `json:"type"`
		Auth     string `json:"keyAuthorization"`
	}{
		Resource: "challenge",
		Type:     challenge.Type,
		Auth:     keyAuth(&config.Key.PublicKey, challenge.Token),
	}
	body, err := jwsEncodeJSON(req, config.Key, nonce)
	if err != nil {
		return Challenge{}, err
	}
	// make the challenge request
	res, err := client.Post(challenge.URI, "application/json", bytes.NewReader(body))
	if err != nil {
		return Challenge{}, err
	}
	defer res.Body.Close()
	// Note: the protocol specifies 200 as the expected response code, but
	// letsencrypt seems to be returning 202.
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		return Challenge{}, responseError(res)
	}

	chalResp := Challenge{}
	if err := json.NewDecoder(res.Body).Decode(&chalResp); err != nil {
		return Challenge{}, fmt.Errorf("Decode: %v", err)
	}

	return chalResp, nil
}

// pollAuthz checks the current status of an authorization request.
//
// If client argument is nil, DefaultClient will be used.
func pollAuthz(client *http.Client, url string) (*Authorization, error) {
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

	var auth Authorization
	if err := json.NewDecoder(res.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}

	return &auth, nil
}

// newCert requests a new certificate.
// The certificate may be returned directly in the cert return value, and/or via
// a long-lived URL in the certURL return value.
//
// If client argument is nil, DefaultClient will be used.
// csr is a DER encoded certificate signing request.
// notBefore and notAfter are optional
func newCert(client *Client, csr []byte, notBefore, notAfter time.Time) (cert *x509.Certificate, certURL string, err error) {
	if client == nil {
		client = http.DefaultClient
	}
	nonce, err := fetchNonce(client, config.Endpoint.CertURL)
	if err != nil {
		return nil, "", err
	}

	// prepare certificate request
	req := struct {
		Resource  string `json:"resource"`
		CSR       string `json:"csr"`
		NotBefore string `json:"notBefore,omitempty"`
		NotAfter  string `json:"notAfter,omitempty"`
	}{
		Resource: "new-cert",
		CSR:      base64.RawURLEncoding.EncodeToString(csr),
	}

	if !notBefore.IsZero() {
		req.NotBefore = notBefore.Format(time.RFC3339)
	}

	if !notAfter.IsZero() {
		req.NotAfter = notAfter.Format(time.RFC3339)
	}

	body, err := jwsEncodeJSON(req, config.Key, nonce)
	if err != nil {
		return nil, "", err
	}

	// make the new-cert request
	res, err := client.Post(config.Endpoint.CertURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, "", responseError(res)
	}

	certURL = res.Header.Get("Location")
	cert = nil

	if res.ContentLength > 0 {
		certBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, "", fmt.Errorf("ReadAll: %v", err)
		}

		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, "", fmt.Errorf("ParseCertificate: %v", err)
		}
	}

	return cert, certURL, nil
}

// Discover performs ACME server discovery using provided url and client.
// If client argument is nil, DefaultClient will be used.
func Discover(client *http.Client, url string) (Endpoint, error) {
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Get(url)
	if err != nil {
		return Endpoint{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Endpoint{}, responseError(res)
	}
	var ep Endpoint
	if json.NewDecoder(res.Body).Decode(&ep); err != nil {
		return Endpoint{}, err
	}
	return ep, nil
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

// keyAuth generates a key authorization string for a given token.
func keyAuth(pub *rsa.PublicKey, token string) string {
	return fmt.Sprintf("%s.%s", token, jwkThumbprint(pub))
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
