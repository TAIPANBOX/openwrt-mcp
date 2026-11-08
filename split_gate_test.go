package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Each test runs one check of scripts/gate-split.sh against the tree and requires it to say ok. The
// scenarios of features/privilege-split.feature bind to these tests, so a scenario cannot lose its
// check and a check cannot lose its scenario (scripts/gate-scenarios-bound.sh). The gate's own teeth,
// the faults it must go red on, are scripts/gate-split-teeth.sh.

func splitCheck(t *testing.T, check string) {
	t.Helper()
	out, err := exec.Command("sh", "scripts/gate-split.sh", check).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok   "+check) {
		t.Fatalf("gate-split.sh %s: %v\n%s", check, err, out)
	}
}

func TestTheListenerRunsAsItsOwnAccountUnderProcd(t *testing.T) {
	splitCheck(t, "check_listener_runs_as_its_account")
}

func TestTheListenersCapabilityFileHoldsNothing(t *testing.T) {
	splitCheck(t, "check_listener_holds_no_capability")
}

func TestTheInitScriptMakesTheAccount(t *testing.T) { splitCheck(t, "check_account_is_made") }

func TestTheHelperDoesNotListenOnTheNetwork(t *testing.T) {
	splitCheck(t, "check_helper_does_not_listen")
}

func TestTheHelperSocketIsTheListenersOnly(t *testing.T) {
	splitCheck(t, "check_socket_is_the_listeners")
}

func TestPackagesShipTheListenersCapabilityFile(t *testing.T) {
	splitCheck(t, "check_packages_ship_the_listener_file")
}

func TestSplitGateHasTeeth(t *testing.T) {
	out, err := exec.Command("sh", "scripts/gate-split-teeth.sh").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "every planted fault is caught") {
		t.Fatalf("gate-split-teeth.sh: %v\n%s", err, out)
	}
}
