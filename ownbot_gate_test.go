package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Each test runs one check of scripts/gate-ownbot.sh against the tree and requires it to say ok. The
// scenarios of features/owner-bot.feature bind to these tests, so a scenario cannot lose its check and
// a check cannot lose its scenario (scripts/gate-scenarios-bound.sh). The gate's own teeth, the faults
// it must go red on, are scripts/gate-ownbot-teeth.sh.

func ownbotCheck(t *testing.T, check string) {
	t.Helper()
	out, err := exec.Command("sh", "scripts/gate-ownbot.sh", check).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok   "+check) {
		t.Fatalf("gate-ownbot.sh %s: %v\n%s", check, err, out)
	}
}

func TestTheOnlyIPSocketsAreTheListenersAndTheStatusProbe(t *testing.T) {
	ownbotCheck(t, "check_ip_sockets_are_the_listeners")
}

func TestTheBotSpeaksToTelegramOnly(t *testing.T) {
	ownbotCheck(t, "check_bot_speaks_to_telegram_only")
}

func TestTheApproversToolsAreRefusedFirstWithTheBot(t *testing.T) {
	ownbotCheck(t, "check_approver_tools_refused_with_the_bot")
}

func TestThePipeIsServedByTheListenerForTheHelperOnly(t *testing.T) {
	ownbotCheck(t, "check_pipe_serves_the_helper_only")
}

func TestTheInitScriptMakesThePipesDirectory(t *testing.T) {
	ownbotCheck(t, "check_init_makes_the_pipe_dir")
}

func TestTheSourceDeletesAFactorBeforeItReadsIt(t *testing.T) {
	ownbotCheck(t, "check_factor_deleted_before_read")
}

func TestTheSourceSaysAFailureByItsWordOnly(t *testing.T) {
	ownbotCheck(t, "check_bot_failures_are_words")
}

func TestOwnbotGateHasTeeth(t *testing.T) {
	out, err := exec.Command("sh", "scripts/gate-ownbot-teeth.sh").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "every planted fault is caught") {
		t.Fatalf("gate-ownbot-teeth.sh: %v\n%s", err, out)
	}
}
