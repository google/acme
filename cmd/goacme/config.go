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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/google/goacme"
)

const (
	// defaultConfig is the default user config file name.
	defaultConfig = "account.json"
	// defaultKey is the default user account private key file.
	defaultKey = "account.key"

	// rsaPrivateKey is a type of RSA key.
	rsaPrivateKey = "RSA PRIVATE KEY"
)

// userConfig is configuration for a single ACME CA account.
type userConfig struct {
	goacme.Account

	// key is stored separately
	key *rsa.PrivateKey
}

// configDir returns local path to goacme config dir.
// It is based on user home dir.
//
// If, for some reason, current user cannot be obtained,
// the return value is empty string.
func configDir() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(u.HomeDir, ".config", "acme")
}

// configFile returns local path of file name using configDir.
func configFile(name string) string {
	return filepath.Join(configDir(), name)
}

// keyPath returns account key tied to the given config file name.
func keyPath(configName string) string {
	ext := filepath.Ext(configName)
	return configName[:len(configName)-len(ext)] + ".key"
}

// readConfig reads userConfig from path and a private key.
// It expects to find the key at the same location,
// by replacing path extention with ".key".
func readConfig(name string) (*userConfig, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	uc := &userConfig{}
	if err := json.Unmarshal(b, uc); err != nil {
		return nil, err
	}
	if key, err := readKey(keyPath(name)); err == nil {
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

// anyKey reads the key from file or generates a new one if gen == true.
// It returns an error if filename exists but cannot be read.
// A newly generated key is also stored to filename.
func anyKey(filename string, gen bool) (*rsa.PrivateKey, error) {
	k, err := readKey(filename)
	if err == nil {
		return k, nil
	}
	if !os.IsNotExist(err) || !gen {
		return nil, err
	}
	k, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return k, writeKey(filename, k)
}

// printAccount outputs account into into w using tabwriter.
func printAccount(w io.Writer, a *goacme.Account, kp string) {
	tw := tabwriter.NewWriter(w, 0, 8, 0, '\t', 0)
	fmt.Fprintln(tw, "URI:\t", a.URI)
	fmt.Fprintln(tw, "Key:\t", kp)
	fmt.Fprintln(tw, "Contact:\t", strings.Join(a.Contact, ", "))
	fmt.Fprintln(tw, "Terms:\t", a.CurrentTerms)
	agreed := a.AgreedTerms
	if a.AgreedTerms == "" {
		agreed = "no"
	} else if a.AgreedTerms == a.CurrentTerms {
		agreed = "yes"
	}
	fmt.Fprintln(tw, "Accepted:\t", agreed)
	// TODO: print authorization and certificates
	tw.Flush()
}
