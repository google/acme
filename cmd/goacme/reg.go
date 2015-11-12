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

import "fmt"

var (
	cmdReg = &command{
		run:       runReg,
		UsageLine: "reg [-c config] [-gen] [-d url]",
		Short:     "new account registration",
		Long: `
Reg creates a new account at an CA specified in the config file.

Default location for the config file is %s.
A new config will be created if one does not exist.

If -gen flag is not specified, and a config file does not exist, the command
will exit with an error.

The -d flag indicates a Directory URL of an ACME CA. It makes sense only
when the config file does not exists and -gen is specified.

See also: goacme help config.
		`,
	}

	regC   *string // -c flag
	regD   = cmdReg.flag.String("d", "https://acme-staging.api.letsencrypt.org/directory", "")
	regGen = cmdReg.flag.Bool("gen", false, "")
)

func init() {
	p := configPath(defaultConfig)
	regC = cmdReg.flag.String("c", p, "")
	cmdReg.Long = fmt.Sprintf(cmdReg.Long, p)
}

func runReg(args []string) {
	//key, err := readKey()
	//if err != nil {
	//	log.Fatal(err)
	//}

	//config, err := goacme.Discover(nil, *directory)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//config.Key = key
	//config.Contact = []string{"mailto:dude@example.com"}
	//if err := goacme.Register(nil, config); err != nil {
	//	log.Fatalf("ERROR: %v", err)
	//}
	//fmt.Printf("%+v", config)
}
