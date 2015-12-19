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
	cmdUpdate = &command{
		UsageLine: "update [-c config] [-accept] [contact [contact ...]]",
		Short:     "update account data",
		Long: `
Update modifies account contact info and accepts the current CA
service agreement which can be seen using whoami command.

Default location for the config file is
%s.
		`,
	}

	updateC      *string // -c flag defined in init()
	updateAccept = cmdUpdate.flag.Bool("accept", false, "")
)

func init() {
	p := configFile(defaultConfig)
	updateC = cmdUpdate.flag.String("c", p, "")
	cmdUpdate.Long = fmt.Sprintf(cmdUpdate.Long, p)
	cmdUpdate.run = runUpdate
}

func runUpdate(args []string) {
	uc, err := readConfig(*updateC)
	if err != nil {
		fatalf("read config: %v", err)
	}
	if uc.key == nil {
		fatalf("no key found for %s", uc.URI)
	}

	client := goacme.Client{Key: uc.key}
	if *updateAccept {
		a, err := client.GetReg(uc.URI)
		if err != nil {
			fatalf(err.Error())
		}
		uc.Account = *a
		uc.AgreedTerms = a.CurrentTerms
	}
	if len(args) != 0 {
		uc.Contact = args
	}

	if err := client.UpdateReg(uc.URI, &uc.Account); err != nil {
		fatalf(err.Error())
	}
	if err := writeConfig(*updateC, uc); err != nil {
		fatalf("write config: %v", err)
	}
	printAccount(os.Stdout, &uc.Account, keyPath(*updateC))
}
