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
	"path/filepath"

	"github.com/google/goacme"
)

var (
	cmdReg = &command{
		run:       runReg,
		UsageLine: "reg [-c config] [-gen] [-d url] [contact [contact ...]]",
		Short:     "new account registration",
		Long: `
Reg creates a new account at a CA using the discovery URL
specified with -d argument. The default value is {{.DefaultDisco}}.
For more information about the discovery run goacme help disco.

Upon successful registration, a new config will be written to {{.AccountFile}}
in the directory specified with -c argument. Default location of the config dir
is {{.ConfigDir}}.
If the config dir does not exist, it will be created.

Contact arguments can be anything: email, phone number, etc.

If -gen flag is not specified, and an account key does not exist, the command
will exit with an error.

See also: goacme help account.
		`,
	}

	regDisco = defaultDiscoFlag
	regGen   bool
)

func init() {
	cmdReg.flag.Var(&regDisco, "d", "")
	cmdReg.flag.BoolVar(&regGen, "gen", regGen, "")
}

func runReg(args []string) {
	key, err := anyKey(filepath.Join(configDir, accountKey), regGen)
	if err != nil {
		fatalf("account key: %v", err)
	}
	uc := &userConfig{
		Account: goacme.Account{Contact: args},
		key:     key,
	}

	// perform discovery to get the reg url
	urls, err := goacme.Discover(nil, string(regDisco))
	if err != nil {
		fatalf("discovery: %v", err)
	}
	// do the registration
	client := goacme.Client{Key: uc.key}
	if err := client.Register(urls.RegURL, &uc.Account); err != nil {
		fatalf("%v", err)
	}
	// success
	// TODO: ask user for agreement acceptance
	if err := writeConfig(uc); err != nil {
		errorf("write config: %v", err)
	}
}
