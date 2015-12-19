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
	"fmt"
	"os"

	"github.com/google/goacme"
)

var (
	cmdWho = &command{
		UsageLine: "whoami [-c config]",
		Short:     "display info about the key holder",
		Long: `
Whoami makes a request to the ACME server signed with a private key
found in the config file and displays the formatted results.

It is a simple way to verify the validity of an account key.

Default location for the config file is
%s.
		`,
	}

	whoC *string // -c flag defined in init()
)

func init() {
	p := configFile(defaultConfig)
	whoC = cmdWho.flag.String("c", p, "")
	cmdWho.Long = fmt.Sprintf(cmdWho.Long, p)
	cmdWho.run = runWhoami
}

func runWhoami([]string) {
	uc, err := readConfig(*whoC)
	if err != nil {
		fatalf("read config: %v", err)
	}
	if uc.key == nil {
		fatalf("no key found for %s", uc.URI)
	}

	client := goacme.Client{Key: uc.key}
	a, err := client.GetReg(uc.URI)
	if err != nil {
		fatalf(err.Error())
	}
	printAccount(os.Stdout, a, keyPath(*whoC))
}
