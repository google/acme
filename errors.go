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

const (
	errtBadCSR       = "urn:acme:error:badCSR"
	errtBadNonce     = "urn:acme:error:badNonce"
	errtConnection   = "urn:acme:error:connection"
	errtDNSSec       = "urn:acme:error:dnssec"
	errtMalformed    = "urn:acme:error:malformed"
	errtInternal     = "urn:acme:error:serverInternal"
	errtTLS          = "urn:acme:error:tls"
	errtUnauthorized = "urn:acme:error:unauthorized"
	errtUnknownHost  = "urn:acme:error:unknownHost"
	errtRateLimited  = "urn:acme:error:rateLimited"
)

// Errors predefined by the ACME spec.
var (
	ErrBadCSR       = &Error{400, errtBadCSR, "CSR is unacceptable"}
	ErrBadNonce     = &Error{400, errtBadNonce, "Unacceptable anti-replay nonce"}
	ErrConnection   = &Error{500, errtConnection, "Could not connect to the client for DV"}
	ErrDNSSec       = &Error{500, errtDNSSec, "Could not validate a DNSSEC signed domain"}
	ErrMalformed    = &Error{400, errtMalformed, "Request message is malformed"}
	ErrInternal     = &Error{500, errtInternal, "Internal Server Error"}
	ErrTLS          = &Error{500, errtTLS, "TLS error during DV"}
	ErrUnauthorized = &Error{401, errtUnauthorized, "Client lacks sufficient authorization"}
	ErrUnknownHost  = &Error{500, errtUnknownHost, "Could not resolve domain name"}
	ErrRateLimited  = &Error{429, errtRateLimited, "Request exceeds rate limit"}
)

// acmeErrors maps ACME error type to a pre-defined error.
var acmeErrors = map[ErrorType]error{
	errtBadCSR:       ErrBadCSR,
	errtBadNonce:     ErrBadNonce,
	errtConnection:   ErrConnection,
	errtDNSSec:       ErrDNSSec,
	errtMalformed:    ErrMalformed,
	errtInternal:     ErrInternal,
	errtTLS:          ErrTLS,
	errtUnauthorized: ErrUnauthorized,
	errtUnknownHost:  ErrUnknownHost,
	errtRateLimited:  ErrRateLimited,
}

// ErrorType is used to define a set of errors predefined by the ACME spec.
type ErrorType string

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
	if err := json.Unmarshal(b, e); err != nil {
		e.Detail = string(b)
		if e.Detail == "" {
			e.Detail = resp.Status
		}
		return e
	}
	if err, ok := acmeErrors[e.Type]; ok {
		return err
	}
	return e
}

// RetryError is a "temporary" error indicating that the request
// can be retried after the specified duration.
type RetryError time.Duration

func (re RetryError) Error() string {
	return fmt.Sprintf("retry after %s", re)
}
