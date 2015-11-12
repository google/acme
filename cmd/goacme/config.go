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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"devrel.googlesource.com/tools/goacme"
)

const (
	// rsaPrivateKey is a type of RSA key.
	rsaPrivateKey = "RSA PRIVATE KEY"

	// defaultConfig is the default user config file name.
	defaultConfig = "config.json"
)

// userConfig is configuration for a single ACME CA account.
type userConfig struct {
	Reg       string          `json:"registration"`
	Contacts  []string        `json:"contacts"`
	Endpoints goacme.Endpoint `json:"endpoints"`
	Agreement string          `json:"agreement"`
	Accepted  bool            `json:"accepted"`
	// key is stored separately
	key *rsa.PrivateKey
}

// configPath returns local file path to a user config.
func configPath(name string) string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(u.HomeDir, ".config", "acme", name)
}

// readConfig reads userConfig from path and a private key.
// It expects to find the key at the same location,
// by replacing path extention with ".key".
func readConfig(path string) (*userConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	uc := &userConfig{}
	if err := json.NewDecoder(f).Decode(uc); err != nil {
		return nil, err
	}
	path = keyPath(path)
	if key, err := readKey(path); err == nil {
		uc.key = key
	}
	return uc, nil
}

// writeConfig writes uc to a file specified by path, creating paret dirs
// along the way. If file does not exists, it will be created with 0600 mod.
// This function does not store uc.key.
func writeConfig(path string, uc *userConfig) error {
	d := filepath.Dir(path)
	if d != "" {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(uc, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, b, 0600)
}

// readKey reads a private rsa key from path.
// The key is expected to be in PEM format.
func readKey(path string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d, _ := pem.Decode(b)
	if d == nil {
		return nil, fmt.Errorf("no block found in %q", path)
	}
	if d.Type != rsaPrivateKey {
		return nil, fmt.Errorf("%q is unsupported", d.Type)
	}
	return x509.ParsePKCS1PrivateKey(d.Bytes)
}

// writeKey writes k to the specified path in PEM format.
// If file does not exists, it will be created with 0600 mod.
func writeKey(path string, k *rsa.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	b := &pem.Block{Type: rsaPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(k)}
	if err := pem.Encode(f, b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// keyPath returns file path to a private key, matching user config file
// specified by path argument.
func keyPath(path string) string {
	ext := filepath.Ext(path)
	return path[:len(path)-len(ext)] + ".key"
}
