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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// ErrorType is used to define a set of errors predefined by the ACME spec.
type ErrorType string

const (
	ErrBadCSR       = "urn:acme:error:badCSR"         // The CSR is unacceptable (e.g., due to a short key)
	ErrBadNonce     = "urn:acme:error:badNonce"       // The client sent an unacceptable anti-replay nonce
	ErrConnection   = "urn:acme:error:connection"     // The server could not connect to the client for DV
	ErrDNSSec       = "urn:acme:error:dnssec"         // The server could not validate a DNSSEC signed domain
	ErrMalformed    = "urn:acme:error:malformed"      // The request message was malformed
	ErrInternal     = "urn:acme:error:serverInternal" // The server experienced an internal error
	ErrTLS          = "urn:acme:error:tls"            // The server experienced a TLS error during DV
	ErrUnauthorized = "urn:acme:error:unauthorized"   // The client lacks sufficient authorization
	ErrUnknownHost  = "urn:acme:error:unknownHost"    // The server could not resolve a domain name
	ErrRateLimited  = "urn:acme:error:rateLimited"    // The request exceeds a rate limit
)

// Error is an ACME error.
type Error struct {
	Code   int `json:"status"`
	Type   ErrorType
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Code, e.Type, e.Detail)
}

// responseError creates an error of Error type from resp.
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

// RetryError is a "temporary" error indicating that the request
// can be retried after the specified duration.
type RetryError time.Duration

func (re RetryError) Error() string {
	return fmt.Sprintf("retry after %s", re)
}
