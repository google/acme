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
	"fmt"
	"os"

	"github.com/google/goacme"
)

var (
	cmdReg = &command{
		UsageLine: "reg [-c config] [-gen] [-d url] [contact [contact ...]]",
		Short:     "new account registration",
		Long: `
Reg creates a new account at an CA specified in the config file
or using discovery URL defined with -d argument.
Contact arguments can be anything: email, phone number, etc.

Default location for the config file is %s.
A new config will be created if one does not exist.

If -gen flag is not specified, and a config file does not exist, the command
will exit with an error. Given an existing configuration file, -gen flag
has no effect.

The -d flag indicates a Directory URL of an ACME CA.

See also: goacme help config.
		`,
	}

	regC   *string // -c flag defined in init()
	regD   = cmdReg.flag.String("d", "https://acme-staging.api.letsencrypt.org/directory", "")
	regGen = cmdReg.flag.Bool("gen", false, "")
)

func init() {
	p := configPath(defaultConfig)
	regC = cmdReg.flag.String("c", p, "")
	cmdReg.Long = fmt.Sprintf(cmdReg.Long, p)
	cmdReg.run = runReg
}

func runReg(args []string) {
	uc, err := readConfig(*regC)
	if err != nil && !os.IsNotExist(err) {
		fatalf("read config: %v", err)
	}
	if os.IsNotExist(err) {
		if !*regGen {
			fatalf("config file does not exist")
		}
		uc = &userConfig{}
	}
	// perform discovery if we don't know new-reg URL
	if uc.Endpoints.RegURL == "" {
		uc.Endpoints, err = goacme.Discover(nil, *regD)
		if err != nil {
			fatalf("discovery: %v", err)
		}
	}
	// at this point we have a config but no key
	// although it may exist initially even w/o the config
	if uc.key == nil {
		uc.key, err = anyKey(keyPath(*regC), *regGen)
	}
	if err != nil {
		fatalf("key error: %v", err)
	}

	// do the registration
	uc.Contacts = args
	cfg := fromUserConfig(uc)
	if err := goacme.Register(nil, cfg); err != nil {
		fatalf("reg: %v", err)
	}
	// success
	uc.Reg = cfg.RegURI
	uc.Endpoints = cfg.Endpoint
	if cfg.TermsURI != "" {
		uc.Agreement = cfg.TermsURI
		uc.Accepted = false
	}
	// TODO: ask user for agreement acceptance
	if err := writeConfig(*regC, uc); err != nil {
		errorf("write config: %v", err)
	}
	if err := writeKey(keyPath(*regC), uc.key); err != nil {
		errorf("write key: %v", err)
	}
}

// anyKey reads the key from file or generates a new one if gen == true.
// It returns an error if keyPath exists but cannot be read.
func anyKey(file string, gen bool) (*rsa.PrivateKey, error) {
	k, err := readKey(file)
	if err == nil {
		return k, nil
	}
	if !os.IsNotExist(err) || !gen {
		return nil, err
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}
