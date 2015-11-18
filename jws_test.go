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
	"encoding/base64"
	"math/big"
	"testing"
)

func TestJWKThumbprint(t *testing.T) {
	// Key example from RFC 7638
	const base64N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
		"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
		"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
		"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
		"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
		"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const base64E = "AQAB"
	const expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	bytes, err := base64.RawURLEncoding.DecodeString(base64N)
	if err != nil {
		t.Fatalf("Error parsing example key N: %v", err)
	}
	n := new(big.Int).SetBytes(bytes)

	bytes, err = base64.RawURLEncoding.DecodeString(base64E)
	if err != nil {
		t.Fatalf("Error parsing example key E: %v", err)
	}
	e := new(big.Int).SetBytes(bytes)

	key := rsa.PublicKey{
		N: n,
		E: int(e.Uint64()),
	}
	th := jwkThumbprint(key)

	if th != expected {
		t.Errorf("th = %q; want %q", th, expected)
	}
}
