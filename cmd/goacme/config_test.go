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
