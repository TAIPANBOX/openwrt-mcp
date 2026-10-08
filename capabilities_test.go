package main

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// A package that grants uci_get on wireless asks the binary first, the way it already asks
// about the PIN: `openwrt-mcp status --json --audit 0`, read with jsonfilter. Decoded here as
// plain JSON rather than into statusReport, so what is asserted is what that caller parses.
func TestCLIStatusJSONSaysUciGetRedactsCredentials(t *testing.T) {
	c := newCLI(t)
	if err := os.WriteFile(c.cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := c.run("", "status", "--json", "--audit", "0")
	if code != 0 {
		t.Fatalf("status: exit %d, %q %q", code, out, errOut)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, out)
	}
	caps, _ := rep["capabilities"].(map[string]any)
	if caps["uci_get_redacts_credentials"] != true {
		t.Errorf("capabilities = %v; a caller cannot tell that uci_get redacts secrets\n%s", rep["capabilities"], out)
	}
}

// The package version is read out of main.go by the Makefile (and by the feed's build script)
// and handed to `apk mkpkg`. apk takes digits and dots, an optional letter, and its own
// suffixes, nothing else: a fork-style "0.5.0-taipanbox.2" would build an .ipk and then fail
// to build the .apk.
func TestVersionIsAValidPackageVersion(t *testing.T) {
	apk := regexp.MustCompile(`^[0-9]+(\.[0-9]+)*[a-z]?(_(alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*$`)
	if !apk.MatchString(version) {
		t.Errorf("version %q is not a version apk accepts", version)
	}
}
