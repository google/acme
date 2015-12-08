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
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"text/template"
	"unicode"
	"unicode/utf8"
)

// A command is an implementation of a goacme command
// like goacme reg or goacme whoami.
type command struct {
	// run runs the command.
	// The args are the arguments after the command name.
	run func(args []string)

	// flag is a set of flags specific to this command.
	flag flag.FlagSet

	// UsageLine is the one-line usage message.
	// The first word in the line is taken to be the command name.
	UsageLine string

	// Short is the short description shown in the 'goacme help' output.
	Short string

	// Long is the long message shown in the 'goacme help <command>' output.
	Long string
}

// Name returns the command's name: the first word in the usage line.
func (c *command) Name() string {
	name := c.UsageLine
	i := strings.IndexRune(name, ' ')
	if i >= 0 {
		name = name[:i]
	}
	return name
}

// Usage reports command's usage, including long description.
func (c *command) Usage() {
	fmt.Fprintf(os.Stderr, "usage: %s\n\n", c.UsageLine)
	fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSpace(c.Long))
	os.Exit(2)
}

// Runnable reports whether the command can be run; otherwise
// it is a documentation pseudo-command.
func (c *command) Runnable() bool {
	return c.run != nil
}

var (
	// commands lists all available commands and help topics.
	// The order here is the order in which they are printed by 'goacme help'.
	commands = []*command{
		cmdReg,
		cmdWho,
	}

	exitMu     sync.Mutex // guards exitStatus
	exitStatus = 0
)

func setExitStatus(n int) {
	exitMu.Lock()
	if exitStatus < n {
		exitStatus = n
	}
	exitMu.Unlock()
}

func exit() {
	os.Exit(exitStatus)
}

var logf = log.Printf

func errorf(format string, args ...interface{}) {
	logf(format, args...)
	setExitStatus(1)
}

func fatalf(format string, args ...interface{}) {
	errorf(format, args...)
	exit()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	log.SetFlags(0)

	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	if args[0] == "help" {
		help(args[1:])
		return
	}

	for _, cmd := range commands {
		if cmd.Name() == args[0] && cmd.Runnable() {
			cmd.flag.Usage = func() { cmd.Usage() }
			cmd.flag.Parse(args[1:])
			cmd.run(cmd.flag.Args())
			exit()
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown subcommand %q.\nRun 'goacme help' for usage.\n", args[0])
	os.Exit(2)
}

func usage() {
	printUsage(os.Stderr)
	os.Exit(2)
}

func printUsage(w io.Writer) {
	bw := bufio.NewWriter(w)
	tmpl(bw, usageTemplate, commands)
	bw.Flush()
}

func help(args []string) {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return
	}
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: goacme help command\n\nToo many arguments given.\n")
		os.Exit(2)
	}

	arg := args[0]
	for _, cmd := range commands {
		if cmd.Name() == arg {
			tmpl(os.Stdout, helpTemplate, cmd)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown help topic %q. Run 'goacme help'.\n", arg)
	os.Exit(2)
}

// tmpl executes the given template text on data, writing the result to w.
func tmpl(w io.Writer, text string, data interface{}) {
	t := template.New("top")
	t.Funcs(template.FuncMap{"trim": strings.TrimSpace, "capitalize": capitalize})
	template.Must(t.Parse(text))
	ew := &errWriter{w: w}
	err := t.Execute(ew, data)
	if ew.err != nil {
		// I/O error writing; ignore write on closed pipe
		if strings.Contains(ew.err.Error(), "pipe") {
			os.Exit(1)
		}
		fatalf("writing output: %v", ew.err)
	}
	if err != nil {
		panic(err)
	}
}

// An errWriter wraps a writer, recording whether a write error occurred.
type errWriter struct {
	w   io.Writer
	err error
}

func (w *errWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err != nil {
		w.err = err
	}
	return n, err
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToTitle(r)) + s[n:]
}

var usageTemplate = `goacme is a client tool for managing certificates
with ACME-compliant servers.

Usage:
	goacme command [arguments]

The commands are:
{{range .}}{{if .Runnable}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use "goacme help [command]" for more information about a command.

Additional help topics:
{{range .}}{{if not .Runnable}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use "goacme help [topic]" for more information about that topic.

`

var helpTemplate = `{{if .Runnable}}usage: goacme {{.UsageLine}}

{{end}}{{.Long | trim}}
`
