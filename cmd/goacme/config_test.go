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

package main

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"

	"devrel.googlesource.com/tools/goacme"
)

func TestConfigReadWrite(t *testing.T) {
	dir, err := ioutil.TempDir("", "goacme-config")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cfg-test.json")
	write := &userConfig{
		Reg:       "https://example.com/acme/reg/123",
		Contacts:  []string{"mailto:dude@example.com"},
		Endpoints: goacme.Endpoint{AuthzURL: "https://authz"},
		Agreement: "https://agreement",
		Accepted:  true,
	}
	if err := writeConfig(path, write); err != nil {
		t.Fatal(err)
	}
	read, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, write) {
		t.Errorf("read: %+v\nwant: %+v", read, write)
	}
}
