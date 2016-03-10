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
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestResponseError(t *testing.T) {
	err500 := &Error{Code: 500, Detail: "500 Internal"}
	errTLS := &Error{Code: 500, Type: ErrTLS, Detail: "TLS err"}
	errCSR := &Error{Code: 400, Type: ErrBadCSR, Detail: "bad CSR"}
	tests := []struct {
		body   string
		status string
		code   int
		err    *Error
	}{
		{"", "500 Internal", 500, err500},
		{`{"type":"urn:acme:error:tls","detail":"TLS err"}`, "500 Server Error", 500, errTLS},
		{`{"type":"urn:acme:error:badCSR","detail":"bad CSR","status":400}`, "500 Server Error", 500, errCSR},
	}
	for i, test := range tests {
		res := &http.Response{
			Body:       ioutil.NopCloser(strings.NewReader(test.body)),
			Status:     test.status,
			StatusCode: test.code,
		}
		err := responseError(res)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("%d: responseError: %+v; want %+v", i, err, test.err)
		}
	}
}
