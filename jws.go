package goacme

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	// TODO: replace this silly library!
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
	sig, err := s.Sign(body, nonce)
	if err != nil {
		return "", err
	}
	return sig.FullSerialize(), nil
}
