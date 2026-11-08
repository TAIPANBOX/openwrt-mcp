package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Each test runs one check of scripts/gate-jail.sh against the tree and requires it to say ok. The
// scenarios of features/service-jail.feature bind to these tests, so a scenario cannot lose its
// check and a check cannot lose its scenario (scripts/gate-scenarios-bound.sh). The gate's own
// teeth, the faults it must go red on, are scripts/gate-jail-teeth.sh.

func jailCheck(t *testing.T, check string) {
	t.Helper()
	out, err := exec.Command("sh", "scripts/gate-jail.sh", check).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok   "+check) {
		t.Fatalf("gate-jail.sh %s: %v\n%s", check, err, out)
	}
}

func TestJailIsRequestedForTheDaemon(t *testing.T) { jailCheck(t, "check_jail_is_requested") }

func TestNoNewPrivsIsSetForTheDaemon(t *testing.T) { jailCheck(t, "check_no_new_privs") }

func TestCapabilitySetIsNamedAndLeavesOutWhatTheDaemonNeverUses(t *testing.T) {
	jailCheck(t, "check_capability_set")
}

func TestJailMountsLeaveOutWhatTheDaemonNeverReads(t *testing.T) { jailCheck(t, "check_mounts") }

func TestSeccompIsInstalledByTheDaemonBeforeItReadsAnything(t *testing.T) {
	jailCheck(t, "check_seccomp_is_in_the_daemon")
}

func TestPackagesShipTheCapabilityFile(t *testing.T) {
	jailCheck(t, "check_packages_ship_the_capability_file")
}

func TestJailGateHasTeeth(t *testing.T) {
	out, err := exec.Command("sh", "scripts/gate-jail-teeth.sh").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "every planted fault is caught") {
		t.Fatalf("gate-jail-teeth.sh: %v\n%s", err, out)
	}
}
