package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wgRig stands in for uci and wg. uci logs every argument list it is given, prints the server
// section when asked for wireguard_server, and keeps whatever it is sent on standard input for
// `uci batch`. wg answers genkey and pubkey with fixed keys, so the test knows what to look for.
func wgRig(t *testing.T) (argvLog, stdinLog string) {
	t.Helper()
	dir := t.TempDir()
	argvLog = filepath.Join(dir, "argv.log")
	stdinLog = filepath.Join(dir, "stdin.log")
	show := filepath.Join(dir, "show.txt")
	err := os.WriteFile(show, []byte("wireguard_server.main=servers\n"+
		"wireguard_server.main.address_v4='10.9.0.1/24'\n"+
		"wireguard_server.main.public_key='SRVPUBLIC='\n"+
		"wireguard_server.main.port='51820'\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fakeCmd(t, "uci", `echo "$*" >> `+argvLog+`
case "$1" in
show) [ "$2" = wireguard_server ] && cat `+show+` ;;
batch) cat > `+stdinLog+` ;;
esac
exit 0`)
	fakeCmd(t, "wg", `case "$1" in
genkey) echo PRIVKEY_FOR_TEST= ;;
pubkey) cat >/dev/null; echo PUBKEY_FOR_TEST= ;;
esac`)
	return argvLog, stdinLog
}

func readOrEmpty(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestWgNewClientKeepsThePrivateKeyOutOfEveryCommandLine(t *testing.T) {
	argvLog, stdinLog := wgRig(t)
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'wg_new_client'\n\tlist scopes '*'\n")

	out, isErr := callTool(t, s, "a", "wg_new_client", map[string]any{"name": "laptop", "endpoint": "vpn.example:51820"})
	if isErr {
		t.Fatalf("wg_new_client failed: %q", out)
	}
	if argv := readOrEmpty(argvLog); strings.Contains(argv, "PRIVKEY_FOR_TEST") {
		t.Errorf("the private key was passed on a command line:\n%s", argv)
	}
	if stdin := readOrEmpty(stdinLog); !strings.Contains(stdin, "PRIVKEY_FOR_TEST") {
		t.Errorf("the private key never reached uci on standard input (batch input %q)", stdin)
	}
}

func TestWgNewClientRefusesAValueThatCannotBeQuotedForUci(t *testing.T) {
	argvLog, _ := wgRig(t)
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'wg_new_client'\n\tlist scopes '*'\n")

	out, isErr := callTool(t, s, "a", "wg_new_client", map[string]any{"name": "it's", "endpoint": "vpn.example:51820"})
	if !isErr {
		t.Errorf("a name with a quote was accepted: %q", out)
	}
	for _, line := range strings.Split(readOrEmpty(argvLog), "\n") {
		if strings.HasPrefix(line, "set") || strings.HasPrefix(line, "batch") || strings.HasPrefix(line, "commit") {
			t.Errorf("uci was asked to write before the name was refused: %q", line)
		}
	}
}
