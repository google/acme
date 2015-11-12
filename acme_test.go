package goacme

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	c, err := Discover(nil, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint.RegURL != reg {
		t.Errorf("RegURL = %q; want %q", c.Endpoint.RegURL, reg)
	}
	if c.Endpoint.AuthzURL != authz {
		t.Errorf("authzURL = %q; want %q", c.Endpoint.AuthzURL, authz)
	}
	if c.Endpoint.CertURL != cert {
		t.Errorf("certURL = %q; want %q", c.Endpoint.CertURL, cert)
	}
	if c.Endpoint.RevokeURL != revoke {
		t.Errorf("revokeURL = %q; want %q", c.Endpoint.RevokeURL, revoke)
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
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Key:      key,
		Endpoint: Endpoint{RegURL: ts.URL},
	}
	if err := Register(nil, cfg); err != nil {
		t.Fatal(err)
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
