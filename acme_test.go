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

package goacme

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Decodes a JWS-encoded request and unmarshals the decoded JSON into a provided
// interface.
func decodeJWSRequest(t *testing.T, v interface{}, r *http.Request) {
	// Decode request
	var req struct{ Payload string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(payload, v)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	const (
		reg    = "https://example.com/acme/new-reg"
		authz  = "https://example.com/acme/new-authz"
		cert   = "https://example.com/acme/new-cert"
		revoke = "https://example.com/acme/revoke-cert"
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{
			"new-reg": %q,
			"new-authz": %q,
			"new-cert": %q,
			"revoke-cert": %q
		}`, reg, authz, cert, revoke)
	}))
	defer ts.Close()
	ep, err := Discover(nil, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ep.RegURL != reg {
		t.Errorf("RegURL = %q; want %q", ep.RegURL, reg)
	}
	if ep.AuthzURL != authz {
		t.Errorf("authzURL = %q; want %q", ep.AuthzURL, authz)
	}
	if ep.CertURL != cert {
		t.Errorf("certURL = %q; want %q", ep.CertURL, cert)
	}
	if ep.RevokeURL != revoke {
		t.Errorf("revokeURL = %q; want %q", ep.RevokeURL, revoke)
	}
}

func TestRegister(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("replay-nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Resource  string
			Contact   []string
			Agreement string
		}
		decodeJWSRequest(t, &j, r)

		// Test request
		if j.Resource != "new-reg" {
			t.Errorf(`resource = %q; want "new-reg"`, j.Resource)
		}
		if len(j.Contact) != 1 || j.Contact[0] != "mailto:admin@example.com" {
			t.Errorf(`contact = %v; want [mailto:admin@example.com]`, j.Contact)
		}
		if j.Agreement != "http://www.example.com" {
			t.Errorf(`agreement = %q; want "http://www.example.com"`, j.Agreement)
		}

		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Key:      key,
		Contact:  []string{"mailto:admin@example.com"},
		Endpoint: Endpoint{RegURL: ts.URL},
		TermsURI: "http://www.example.com",
	}
	// Test response handling
	if err := Register(nil, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("replay-nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Resource   string
			Identifier AuthzIdentifier
		}
		decodeJWSRequest(t, &j, r)

		// Test request
		if j.Resource != "new-authz" {
			t.Errorf(`resource = %q; want "new-authz"`, j.Resource)
		}
		if j.Identifier.Type != "dns" {
			t.Errorf(`identifier.type = %q; want "dns"`, j.Identifier.Type)
		}
		if j.Identifier.Value != "example.com" {
			t.Errorf(`identifier.value = %q; want "example.com"`, j.Identifier.Value)
		}

		w.Header().Set("Location", "https://ca.tld/acme/auth/1")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{
			"identifier": {"type":"dns","value":"example.com"},
			"status":"pending",
			"challenges":[
				{
					"type":"http-01",
					"status":"pending",
					"uri":"https://ca.tld/acme/challenge/publickey/id1",
					"token":"token1"
				},
				{
					"type":"tls-sni-01",
					"status":"pending",
					"uri":"https://ca.tld/acme/challenge/publickey/id2",
					"token":"token2"
				}
			],
			"combinations":[[0],[1]]}`)
	}))
	defer ts.Close()
	cfg := &Config{
		Key:      testKey,
		Endpoint: Endpoint{AuthzURL: ts.URL},
	}

	// Test response handling
	auth, err := authorize(nil, cfg, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if auth.URI != "https://ca.tld/acme/auth/1" {
		t.Errorf(`URI = %q; want "https://ca.tld/acme/auth/1"`, auth.URI)
	}
	if auth.Status != "pending" {
		t.Errorf(`Status = %q; want "pending"`, auth.Status)
	}
	if auth.Identifier.Type != "dns" {
		t.Errorf(`Identifier.Type = %q; want "dns"`, auth.Identifier.Type)
	}
	if auth.Identifier.Value != "example.com" {
		t.Errorf(`Identifier.Value = %q; want "example.com"`, auth.Identifier.Value)
	}

	set := auth.ChallengeSet
	if n := len(set.Challenges); n != 2 {
		t.Fatalf("len(set.Challenges) = %d; want 2", n)
	}

	c := set.Challenges[0]
	if c.Type != "http-01" {
		t.Errorf("c.Type = %q; want http-01", c.Type)
	}
	if c.URI != "https://ca.tld/acme/challenge/publickey/id1" {
		t.Errorf("c.URI = %q; want https://ca.tld/acme/challenge/publickey/id1", c.URI)
	}
	if c.Token != "token1" {
		t.Errorf("c.Token = %q; want token1", c.Type)
	}

	c = set.Challenges[1]
	if c.Type != "tls-sni-01" {
		t.Errorf("c.Type = %q; want tls-sni-01", c.Type)
	}
	if c.URI != "https://ca.tld/acme/challenge/publickey/id2" {
		t.Errorf("c.URI = %q; want https://ca.tld/acme/challenge/publickey/id2", c.URI)
	}
	if c.Token != "token2" {
		t.Errorf("c.Token = %q; want token2", c.Type)
	}

	combs := [][]int{[]int{0}, []int{1}}
	if !reflect.DeepEqual(set.Combinations, combs) {
		t.Errorf("set.Combinations: %+v\nwant: %+v\n", set.Combinations, combs)
	}
}

func TestPollAuthz(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("r.Method = %q; want GET", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"identifier": {"type":"dns","value":"example.com"},
			"status":"pending",
			"challenges":[
				{
					"type":"http-01",
					"status":"pending",
					"uri":"https://ca.tld/acme/challenge/publickey/id1",
					"token":"token1"
				},
				{
					"type":"tls-sni-01",
					"status":"pending",
					"uri":"https://ca.tld/acme/challenge/publickey/id2",
					"token":"token2"
				}
			],
			"combinations":[[0],[1]]}`)
	}))
	defer ts.Close()

	// Test response handling
	auth, err := pollAuthz(nil, ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if auth.Status != "pending" {
		t.Errorf(`Status = %q; want "pending"`, auth.Status)
	}
	if auth.Identifier.Type != "dns" {
		t.Errorf(`Identifier.Type = %q; want "dns"`, auth.Identifier.Type)
	}
	if auth.Identifier.Value != "example.com" {
		t.Errorf(`Identifier.Value = %q; want "example.com"`, auth.Identifier.Value)
	}

	set := auth.ChallengeSet
	if n := len(set.Challenges); n != 2 {
		t.Fatalf("len(set.Challenges) = %d; want 2", n)
	}

	c := set.Challenges[0]
	if c.Type != "http-01" {
		t.Errorf("c.Type = %q; want http-01", c.Type)
	}
	if c.URI != "https://ca.tld/acme/challenge/publickey/id1" {
		t.Errorf("c.URI = %q; want https://ca.tld/acme/challenge/publickey/id1", c.URI)
	}
	if c.Token != "token1" {
		t.Errorf("c.Token = %q; want token1", c.Type)
	}

	c = set.Challenges[1]
	if c.Type != "tls-sni-01" {
		t.Errorf("c.Type = %q; want tls-sni-01", c.Type)
	}
	if c.URI != "https://ca.tld/acme/challenge/publickey/id2" {
		t.Errorf("c.URI = %q; want https://ca.tld/acme/challenge/publickey/id2", c.URI)
	}
	if c.Token != "token2" {
		t.Errorf("c.Token = %q; want token2", c.Type)
	}

	combs := [][]int{[]int{0}, []int{1}}
	if !reflect.DeepEqual(set.Combinations, combs) {
		t.Errorf("set.Combinations: %+v\nwant: %+v\n", set.Combinations, combs)
	}
}

func TestAcceptChallenge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("replay-nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Resource string
			Type     string
			Auth     string `json:"keyAuthorization"`
		}
		decodeJWSRequest(t, &j, r)

		// Test request
		if j.Resource != "challenge" {
			t.Errorf(`resource = %q; want "challenge"`, j.Resource)
		}
		if j.Type != "http-01" {
			t.Errorf(`type = %q; want "http-01"`, j.Type)
		}
		keyAuth := "token1." + testKeyThumbprint
		if j.Auth != keyAuth {
			t.Errorf(`keyAuthorization = %q; want %q`, j.Auth, keyAuth)
		}

		// Respond to request
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{
			"type":"http-01",
			"status":"pending",
			"uri":"https://ca.tld/acme/challenge/publickey/id1",
			"token":"token1",
			"keyAuthorization":%q
		}`, keyAuth)
	}))
	defer ts.Close()

	// Test response handling
	c, err := acceptChallenge(nil, &Config{Key: testKey}, Challenge{
		URI:   ts.URL,
		Token: "token1",
		Type:  "http-01",
	})
	if err != nil {
		t.Fatal(err)
	}

	if c.Type != "http-01" {
		t.Errorf("c.Type = %q; want http-01", c.Type)
	}
	if c.URI != "https://ca.tld/acme/challenge/publickey/id1" {
		t.Errorf("c.URI = %q; want https://ca.tld/acme/challenge/publickey/id1", c.URI)
	}
	if c.Token != "token1" {
		t.Errorf("c.Token = %q; want token1", c.Type)
	}
}

func TestFetchNonce(t *testing.T) {
	tests := []struct {
		code  int
		nonce string
	}{
		{http.StatusOK, "nonce1"},
		{http.StatusBadRequest, "nonce2"},
		{http.StatusOK, ""},
	}
	var i int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("%d: r.Method = %q; want HEAD", i, r.Method)
		}
		w.Header().Set("replay-nonce", tests[i].nonce)
		w.WriteHeader(tests[i].code)
	}))
	defer ts.Close()
	for ; i < len(tests); i++ {
		test := tests[i]
		n, err := fetchNonce(http.DefaultClient, ts.URL)
		if n != test.nonce {
			t.Errorf("%d: n=%q; want %q", i, n, test.nonce)
		}
		switch {
		case err == nil && test.nonce == "":
			t.Errorf("%d: n=%q, err=%v; want non-nil error", i, n, err)
		case err != nil && test.nonce != "":
			t.Errorf("%d: n=%q, err=%v; want %q", i, n, err, test.nonce)
		}
	}
}

func TestParseLinkHeader(t *testing.T) {
	h := http.Header{"Link": {
		`<https://example.com/acme/new-authz>;rel="next"`,
		`<https://example.com/acme/recover-reg>; rel=recover`,
		`<https://example.com/acme/terms>; foo=bar; rel="terms-of-service"`,
	}}
	tests := []struct{ in, out string }{
		{"next", "https://example.com/acme/new-authz"},
		{"recover", "https://example.com/acme/recover-reg"},
		{"terms-of-service", "https://example.com/acme/terms"},
		{"empty", ""},
	}
	for i, test := range tests {
		if v := parseLinkHeader(h, test.in); v != test.out {
			t.Errorf("%d: parseLinkHeader(%q): %q; want %q", i, test.in, v, test.out)
		}
	}
}
