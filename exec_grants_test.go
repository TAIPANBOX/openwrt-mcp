package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// standInProgram puts a program on PATH that appends its arguments to a log when it runs, so a
// test can tell "refused and never started" from "started and failed".
func standInProgram(t *testing.T, name string) string {
	t.Helper()
	log := filepath.Join(t.TempDir(), name+".ran")
	fakeCmd(t, name, `echo "$*" >> `+log)
	return log
}

func started(log string) bool {
	_, err := os.Stat(log)
	return err == nil
}

func TestExecProgramGrantedWithoutArgumentsRunsWithNone(t *testing.T) {
	log := standInProgram(t, "fakeprog")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'fakeprog'\n")

	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"fakeprog", "-v"}}); !isErr || started(log) {
		t.Errorf("a program granted with no argument list ran with one: %q (error=%v)", out, isErr)
	}
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"fakeprog"}}); isErr || !started(log) {
		t.Errorf("the program run with no arguments was refused: %q (error=%v)", out, isErr)
	}
}

func TestExecArgumentListAllowsExactlyWhatItNames(t *testing.T) {
	log := standInProgram(t, "fakeprog")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'fakeprog'\n"+
		"\tlist argv 'fakeprog -l *'\n\tlist argv 'fakeprog --version'\n")

	for _, argv := range [][]string{{"fakeprog", "-l", "50"}, {"fakeprog", "-l", "5"}, {"fakeprog", "--version"}} {
		os.Remove(log)
		if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": argv}); isErr || !started(log) {
			t.Errorf("listed form %v was refused: %q (error=%v)", argv, out, isErr)
		}
	}
	for _, argv := range [][]string{
		{"fakeprog", "-f"},            // a different flag
		{"fakeprog", "-l"},            // the value is dropped
		{"fakeprog", "-l", "50", "x"}, // one more argument than the list
		{"fakeprog"},                  // the bare program is not a listed form either
		{"fakeprog", "--Version"},     // case is part of the argument
	} {
		os.Remove(log)
		if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": argv}); !isErr || started(log) {
			t.Errorf("unlisted form %v ran: %q (error=%v)", argv, out, isErr)
		}
	}
}

func TestExecArgumentPatternMatchesOneArgumentWithoutReachingUp(t *testing.T) {
	log := standInProgram(t, "fakeprog")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'fakeprog'\n"+
		"\tlist argv 'fakeprog /etc/config/*'\n")

	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"fakeprog", "/etc/config/network"}}); isErr || !started(log) {
		t.Errorf("a file inside the granted directory was refused: %q (error=%v)", out, isErr)
	}
	for _, argv := range [][]string{
		{"fakeprog", "/etc/shadow"},
		{"fakeprog", "/etc/config/../shadow"},
		{"fakeprog", "/etc/config/.."},
		{"fakeprog", "/etc/config/a/b"},
		{"fakeprog", "/etc/config/network", "extra"},
	} {
		os.Remove(log)
		if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": argv}); !isErr || started(log) {
			t.Errorf("argument outside the pattern ran: %v: %q (error=%v)", argv, out, isErr)
		}
	}
}

func TestExecArgvNamesOnlyGrantedProgramsAndExec(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"program not granted": "config policy\n\toption client 'a'\n\tlist tools 'exec'\n" +
			"\tlist scopes 'cat'\n\tlist argv 'sh -c *'\n",
		"no exec tool": "config policy\n\toption client 'a'\n\tlist tools 'logread'\n" +
			"\tlist scopes 'logread'\n\tlist argv 'logread -l *'\n",
	}
	for name, body := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: a config with a dead argument list loaded", name)
		}
	}
}

func TestExecArgumentListBelongsToItsOwnPolicy(t *testing.T) {
	log := standInProgram(t, "fakeprog")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'fakeprog'\n"+
		"config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'fakeprog'\n"+
		"\tlist argv 'fakeprog -l *'\n")

	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"fakeprog", "-l", "5"}}); isErr || !started(log) {
		t.Errorf("the form the second policy names was refused: %q (error=%v)", out, isErr)
	}
	os.Remove(log)
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"fakeprog", "-f"}}); !isErr || started(log) {
		t.Errorf("one policy's argument list widened the other's grant: %q (error=%v)", out, isErr)
	}
}

func TestExecRefusedArgumentsAreAuditedAsDenied(t *testing.T) {
	standInProgram(t, "fakeprog")
	s, dir := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'fakeprog'\n"+
		"\tlist argv 'fakeprog -l *'\n")

	callTool(t, s, "a", "exec", map[string]any{"argv": []string{"fakeprog", "-f"}})
	evs := auditEvents(t, dir)
	if len(evs) != 1 || evs[0].Outcome != OutcomeDenied {
		t.Errorf("audit = %+v, want one DENIED", evs)
	}
}
