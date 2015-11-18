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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	jose "github.com/letsencrypt/go-jose"
)

type jwsHeader struct {
	Alg   string `json:"alg"`
	Typ   string `json:"typ"`
	JWK   string `json:"jwk"`
	Nonce string `json:"nonce"`
}

func (h *jwsHeader) encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func jwsEncode(claims interface{}, key *rsa.PrivateKey, nonce string) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	s, err := jose.NewSigner(jose.RS256, key)
	if err != nil {
		return "", err
	}
	s.SetNonceSource(staticNonceSource(nonce))
	sig, err := s.Sign(body)
	if err != nil {
		return "", err
	}
	return sig.FullSerialize(), nil
}

type staticNonceSource string

func (s staticNonceSource) Nonce() (string, error) {
	return string(s), nil
}

func jwkThumbprint(key rsa.PublicKey) string {
	n := key.N
	e := big.NewInt(int64(key.E))
	jwk := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		base64.RawURLEncoding.EncodeToString(e.Bytes()),
		base64.RawURLEncoding.EncodeToString(n.Bytes()))
	hash := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
