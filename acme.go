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

// Account is a user account. It is associated with a private key.
type Account struct {
	// URI is the account unique ID, which is also a URL used to retrieve
	// account data from the CA.
	URI string `json:"uri"`

	// Contact is a slice of contact info used during registration.
	Contact []string `json:"contact"`

	// The terms user has agreed to.
	// Zero value indicates that the user hasn't agreed yet.
	AgreedTerms string `json:"agreement"`

	// Actual terms of a CA.
	CurrentTerms string `json:"terms"`

	// Authz is the authorization URL used to initiate a new authz flow.
	Authz string `json:"authz"`

	// Authorizations is a URI from which a list of authorizations
	// granted to this account can be fetched via a GET request.
	Authorizations string `json:"authorizations"`

	// Certificates is a URI from which a list of certificates
	// issued for this account can be fetched via a GET request.
	Certificates string `json:"certificates"`
}

// Endpoint is ACME server directory.
type Endpoint struct {
	RegURL    string `json:"new-reg"`
	AuthzURL  string `json:"new-authz"`
	CertURL   string `json:"new-cert"`
	RevokeURL string `json:"revoke-cert"`
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

// Authorization encodes an authorization response.
type Authorization struct {
	ChallengeSet
	Identifier AuthzID
	URI        string
	Status     string
}

// AuthzID encodes an ID for something to authorize, typically a domain.
type AuthzID struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// Client implements ACME spec.
type Client struct {
	http.Client
	Key *rsa.PrivateKey
}

// CertSource creates new CertSource using client c.
func (c *Client) CertSource() CertSource {
	// not implemented
	return nil
}

// CreateCert requests a new certificate.
// It always returns a non-empty long-lived certURL.
// The cert, however, may be nil even if no error occurred.
//
// url is typically an Endpoint.CertURL.
// csr is a DER encoded certificate signing request.
// notBefore and notAfter are optional.
func (c *Client) CreateCert(url string, csr []byte, notBefore, notAfter time.Time) (cert *x509.Certificate, certURL string, err error) {
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

	res, err := c.PostJWS(url, req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, "", responseError(res)
	}

	cert = nil
	if res.ContentLength > 0 {
		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, "", fmt.Errorf("ReadAll: %v", err)
		}
		cert, err = x509.ParseCertificate(b)
		if err != nil {
			return nil, "", fmt.Errorf("ParseCertificate: %v", err)
		}
	}
	return cert, res.Header.Get("Location"), nil
}

// Register create a new registration by following the "new-reg" flow.
// It populates the a argument with the response received from the server.
// Existing field values may be overwritten.
//
// The url argument is typically an Endpoint.RegURL.
func (c *Client) Register(url string, a *Account) error {
	return c.doReg(url, a, "new-reg")
}

// GetReg retrieves an existing registration.
// The url argument is an Account.URI, usually obtained with c.Register.
func (c *Client) GetReg(url string) (*Account, error) {
	a := &Account{}
	return a, c.doReg(url, a, "reg")
}

// UpdateReg updates existing registration.
// It populates the a argument with the response received from the server.
// Existing field values may be overwritten.
//
// The url argument is an Account.URI, usually obtained with c.Register.
func (c *Client) UpdateReg(url string, a *Account) error {
	return c.doReg(url, a, "reg")
}

// Authorize performs the initial step in an authorization flow.
// The caller will then need to choose from and perform a set of returned
// challenges using c.Accept in order to successfully complete authorization.
//
// The url argument is an authz URL, usually obtained with c.Register.
func (c *Client) Authorize(url, domain string) (*Authorization, error) {
	req := struct {
		Resource   string  `json:"resource"`
		Identifier AuthzID `json:"identifier"`
	}{
		Resource:   "new-authz",
		Identifier: AuthzID{Type: "dns", Value: domain},
	}
	res, err := c.PostJWS(url, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, responseError(res)
	}

	var az Authorization
	if err := json.NewDecoder(res.Body).Decode(&az); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	az.URI = res.Header.Get("Location")
	if az.Status != "pending" {
		return nil, fmt.Errorf("Unexpected status: %s", az.Status)
	}
	return &az, nil
}

// GetAuthz retrieves the current status of an authorization flow.
//
// A client typically polls an authz status using this method.
func (c *Client) GetAuthz(url string) (*Authorization, error) {
	res, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	az := &Authorization{URI: url}
	if err := json.NewDecoder(res.Body).Decode(az); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	return az, nil
}

// Accept informs the server that the client accepts one of its challenges
// previously obtained with c.Authorize.
//
// The server will then perform the validation asynchronously.
func (c *Client) Accept(chal *Challenge) (*Challenge, error) {
	req := struct {
		Resource string `json:"resource"`
		Type     string `json:"type"`
		Auth     string `json:"keyAuthorization"`
	}{
		Resource: "challenge",
		Type:     chal.Type,
		Auth:     keyAuth(&c.Key.PublicKey, chal.Token),
	}
	res, err := c.PostJWS(chal.URI, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// Note: the protocol specifies 200 as the expected response code, but
	// letsencrypt seems to be returning 202.
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		return nil, responseError(res)
	}

	var rc Challenge
	if err := json.NewDecoder(res.Body).Decode(&rc); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	return &rc, nil
}

// PostJWS makes a request to the specified url with JWS-signed body.
// The body argument must be JSON-serializable.
func (c *Client) PostJWS(url string, body interface{}) (*http.Response, error) {
	nonce, err := fetchNonce(&c.Client, url)
	if err != nil {
		return nil, err
	}
	b, err := jwsEncodeJSON(body, c.Key, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// doReg sends all types of registration requests.
// The type of request is identified by typ argument, which is a "resource"
// in the ACME spec terms.
//
// A non-nil acct argument indicates whether the intention is to mutate data
// of the Account. Only Contact and Agreement of its fields are used
// in such cases.
//
// The fields of acct will be populate with the server response
// and may be overwritten.
func (c *Client) doReg(url string, acct *Account, typ string) error {
	req := struct {
		Resource  string   `json:"resource"`
		Contact   []string `json:"contact,omitempty"`
		Agreement string   `json:"agreement,omitempty"`
	}{
		Resource: typ,
	}
	if acct != nil {
		req.Contact = acct.Contact
		req.Agreement = acct.AgreedTerms
	}
	res, err := c.PostJWS(url, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return responseError(res)
	}

	if err := json.NewDecoder(res.Body).Decode(acct); err != nil {
		return fmt.Errorf("Decode: %v", err)
	}
	acct.URI = res.Header.Get("Location")
	if v := parseLinkHeader(res.Header, "terms-of-service"); v != "" {
		acct.CurrentTerms = v
	}
	if v := parseLinkHeader(res.Header, "next"); v != "" {
		acct.Authz = v
	}
	return nil
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
