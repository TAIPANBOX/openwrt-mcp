package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The guess throttle of the second factor. The store is driven on a testClock throughout, so a
// wall clock that jumps and a monotonic clock that does not are two different things here, as
// they are on a router with no battery.

var (
	wrongPIN = unlockAttempt{PIN: "0000"}
	rightPIN = unlockAttempt{PIN: "4821"}
)

func pinPolicy() unlockPolicy { return policyFor(factorPIN) }

// restart is a daemon starting over the same state directory: a new store, on a monotonic clock
// that begins again, which is a process restart and a reboot alike. The wall clock goes on, or
// does not, as the caller's clock says.
func restart(t *testing.T, dir string, clk *testClock) *MFAStore {
	t.Helper()
	m, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	clk.mono = 0
	setStoreClock(m, clk.now)
	return m
}

func mustBeRefused(t *testing.T, m *MFAStore, client string, in unlockAttempt, up unlockPolicy, clk *testClock, why string) {
	t.Helper()
	_, err := m.Attempt(client, in, up, clk.wall)
	if err == nil || !strings.Contains(err.Error(), "locked out") {
		t.Fatalf("%s: got %v, want a lockout refusal", why, err)
	}
}

func mustOpen(t *testing.T, m *MFAStore, client string, in unlockAttempt, up unlockPolicy, clk *testClock, why string) {
	t.Helper()
	if _, err := m.Attempt(client, in, up, clk.wall); err != nil {
		t.Fatalf("%s: %v", why, err)
	}
}

func fail(t *testing.T, m *MFAStore, client string, up unlockPolicy, clk *testClock, times int) {
	t.Helper()
	for i := 0; i < times; i++ {
		_, err := m.Attempt(client, wrongPIN, up, clk.wall)
		if err == nil {
			t.Fatal("a wrong PIN unlocked")
		}
		if strings.Contains(err.Error(), "locked out") {
			t.Fatalf("failure %d of %d was refused instead of counted: %v", i+1, times, err)
		}
	}
}

// reach counts n failures, waiting out each delay on the way.
func reach(t *testing.T, m *MFAStore, client string, up unlockPolicy, clk *testClock, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		fail(t, m, client, up, clk, 1)
		if i < n {
			clk.pass(delayAfter(i, up))
		}
	}
}

func throttleLines(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(readFile(t, filepath.Join(dir, "throttle")), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func writeThrottleFixture(t *testing.T, dir, body string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "throttle"), body)
}

func TestDelayScheme(t *testing.T) {
	m5 := unlockPolicy{MaxFailures: 5, Lockout: 15 * time.Minute}
	for n, want := range map[int]time.Duration{
		0: 0, 1: 0, 4: 0,
		5: 15 * time.Minute, 6: 30 * time.Minute, 7: time.Hour, 8: time.Hour, 500: time.Hour,
		throttleMaxCount: time.Hour,
	} {
		if got := delayAfter(n, m5); got != want {
			t.Errorf("after %d failures: %v, want %v", n, got, want)
		}
	}
	for name, c := range map[string]struct {
		up   unlockPolicy
		n    int
		want time.Duration
	}{
		"a first delay of 20m doubles past the hour and stops at it": {unlockPolicy{MaxFailures: 5, Lockout: 20 * time.Minute}, 7, time.Hour},
		"a first delay of 7m reaches 56m before the hour":            {unlockPolicy{MaxFailures: 5, Lockout: 7 * time.Minute}, 8, 56 * time.Minute},
		"a first delay over the hour is the ceiling":                 {unlockPolicy{MaxFailures: 5, Lockout: 2 * time.Hour}, 9, 2 * time.Hour},
		"a limit of one": {unlockPolicy{MaxFailures: 1, Lockout: time.Minute}, 1, time.Minute},
		"a day-long first delay does not overflow": {unlockPolicy{MaxFailures: 1, Lockout: 24 * time.Hour}, 1 << 30, 24 * time.Hour},
	} {
		if got := delayAfter(c.n, c.up); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestFiveFreeTriesThenFifteenThirtySixty(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()

	fail(t, m, "a", up, clk, 5)
	for _, delay := range []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, time.Hour, time.Hour} {
		clk.pass(delay - time.Second)
		mustBeRefused(t, m, "a", wrongPIN, up, clk, fmt.Sprintf("a second before the end of a delay of %v", delay))
		clk.pass(time.Second)
		fail(t, m, "a", up, clk, 1)
	}
	if st := m.State("a", clk.wall); st.Failures != 10 {
		t.Errorf("failures = %d, want 10", st.Failures)
	}
}

func TestConfiguredLimitAndDelayKeepTheirMeaning(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := unlockPolicy{Factor: factorPIN, Window: time.Minute, MaxFailures: 3, Lockout: 5 * time.Minute}

	fail(t, m, "a", up, clk, 2)
	if st := m.State("a", clk.wall); !st.LockedOutUntil.IsZero() {
		t.Fatalf("locked before mfa_max_failures: %+v", st)
	}
	fail(t, m, "a", up, clk, 1)
	st := m.State("a", clk.wall)
	if want := clk.wall.Add(5 * time.Minute); !st.LockedOutUntil.Equal(want) {
		t.Fatalf("the first delay ends %v, want mfa_lockout from now: %v", st.LockedOutUntil, want)
	}
	clk.pass(5 * time.Minute)
	fail(t, m, "a", up, clk, 1)
	if st := m.State("a", clk.wall); !st.LockedOutUntil.Equal(clk.wall.Add(10 * time.Minute)) {
		t.Errorf("the second delay ends %v, want twice mfa_lockout", st.LockedOutUntil)
	}
}

func TestRestartMidDelayStartsAFreshDelay(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()

	fail(t, m, "a", up, clk, 5)
	clk.pass(15 * time.Minute)
	fail(t, m, "a", up, clk, 1) // six failures: a wait of 30 minutes
	clk.pass(10 * time.Minute)

	m = restart(t, dir, clk)
	mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN straight after a restart inside a delay")
	if st := m.StateUnder("a", up, clk.wall); st.Failures != 6 || !st.LockedOutUntil.Equal(clk.wall.Add(30*time.Minute)) {
		t.Errorf("after the restart: %+v, want 6 failures and a fresh delay of 30m", st)
	}
	clk.pass(30*time.Minute - time.Second)
	mustBeRefused(t, m, "a", rightPIN, up, clk, "a second before the fresh delay ends")
	clk.pass(time.Second)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after the fresh delay")
}

// A restart costs at most one more delay: a client that was already past its delay meets one
// more, and only that.
func TestARestartBelowTheLimitChangesNothing(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 3)
	m = restart(t, dir, clk)
	if st := m.StateUnder("a", up, clk.wall); st.Failures != 3 || !st.LockedOutUntil.IsZero() {
		t.Fatalf("after the restart: %+v", st)
	}
	fail(t, m, "a", up, clk, 1)
	mustOpen(t, m, "a", rightPIN, up, clk, "the fifth try, after a restart with three failures")
}

func TestRebootWithTheClockJumping(t *testing.T) {
	for name, jump := range map[string]time.Duration{
		"forward, as ntpd corrects an old clock":       3 * 365 * 24 * time.Hour,
		"backward, to the newest file in /etc on boot": -3 * 365 * 24 * time.Hour,
		"forward, just past the end of the delay":      61 * time.Minute,
		"backward, before the last failure":            -61 * time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			m, dir := enrolled(t, "4821", "a")
			clk := useClock(m)
			up := pinPolicy()
			reach(t, m, "a", up, clk, 7) // a wait of an hour

			m = restart(t, dir, clk)
			clk.jump(jump)
			mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN straight after the reboot")
			clk.pass(59 * time.Minute)
			clk.jump(jump)
			mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN with the clock stepped again, a minute short")
			if got := m.StateUnder("a", up, clk.wall).Failures; got != 7 {
				t.Errorf("failures = %d after the reboot, want 7", got)
			}
			clk.pass(time.Minute)
			mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN an hour of uptime after the reboot")
		})
	}
}

func TestAClockJumpInsideADelayChangesNothing(t *testing.T) {
	for name, jump := range map[string]time.Duration{
		"forward":                     10 * 365 * 24 * time.Hour,
		"backward":                    -10 * 365 * 24 * time.Hour,
		"forward to the end instant":  15 * time.Minute,
		"backward by exactly a delay": -15 * time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := enrolled(t, "4821", "a")
			clk := useClock(m)
			up := pinPolicy()
			fail(t, m, "a", up, clk, 5)

			clk.jump(jump)
			mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN after the clock stepped inside the delay")
			clk.pass(15*time.Minute - time.Second)
			mustBeRefused(t, m, "a", rightPIN, up, clk, "a second before the end, on the monotonic clock")
			clk.pass(time.Second)
			mustOpen(t, m, "a", rightPIN, up, clk, "the end of the delay, on the monotonic clock")
		})
	}
}

// What the refusal says is the wall clock's reading of what is left, so it moves with the clock
// while the delay does not.
func TestTheRefusalNamesWhenTheWallClockWillSayTheDelayEnds(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	clk.pass(5 * time.Minute)
	clk.jump(time.Hour)
	_, err := m.Attempt("a", wrongPIN, up, clk.wall)
	want := clk.wall.Add(10 * time.Minute).Format(time.RFC3339)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %v, want the end %s", err, want)
	}
}

// hermes-openwrt's plugin reads these words and the time after them. A change here breaks a
// contract with another repository without anything in this one going red.
func TestRefusalWordsAreThePluginsContract(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	_, err := m.Attempt("a", wrongPIN, up, clk.wall)
	end := clk.wall.Add(15 * time.Minute).Format(time.RFC3339)
	if err == nil || err.Error() != "too many failed attempts: unlocking is locked out until "+end {
		t.Errorf("the refusal reads %q", err)
	}
}

func TestDiskHoldsOnlyACountAndAStep(t *testing.T) {
	m, dir := enrolled(t, "4821", "a", "b")
	clk := useClock(m)
	up := policyFor(factorPINTOTP)
	fail(t, m, "a", up, clk, 3)
	code := codeNow(t, m, "b", clk.wall)
	mustOpen(t, m, "b", unlockAttempt{PIN: "4821", Code: code}, up, clk, "b")

	lines := throttleLines(t, dir)
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	step := uint64(clk.wall.Unix()) / 30
	if want := []string{"a 3 0", fmt.Sprintf("b 0 %d", step)}; lines[0] != want[0] || lines[1] != want[1] {
		t.Errorf("the file holds %q, want %q", lines, want)
	}
	// Whatever else the file might come to hold, it holds no reading of any clock but the step,
	// and the step is thirty seconds wide and only ever a code's.
	body := readFile(t, filepath.Join(dir, "throttle"))
	for _, clock := range []string{strconv.FormatInt(clk.wall.Unix(), 10), clk.wall.Format("2006"), clk.wall.Format(time.RFC3339)} {
		if strings.Contains(body, clock) {
			t.Errorf("the file holds a time, %q: %s", clock, body)
		}
	}
	if st, _ := os.Stat(filepath.Join(dir, "throttle")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
	if !strings.HasPrefix(body, "# openwrt-mcp second-factor throttle, format 1.") {
		t.Errorf("no header: %q", body)
	}
}

// The count must be on the disk before any factor is looked at, or a process that dies between
// the check and the write has given a free guess. The step is the witness: checkFactorsLocked
// spends it, so a first write that finds it unspent came first.
func TestTheCountIsOnDiskBeforeTheFactorsAreChecked(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := policyFor(factorTOTP)
	var writes []string
	var stepAtFirstWrite uint64 = 1
	real := func(path string, data []byte) error { return atomicWriteFile(path, data, 0o600) }
	setThrottleWriter(m, func(path string, data []byte) error {
		if len(writes) == 0 {
			stepAtFirstWrite = m.lastCtr["a"]
		}
		writes = append(writes, string(data))
		return real(path, data)
	})
	mustOpen(t, m, "a", unlockAttempt{Code: codeNow(t, m, "a", clk.wall)}, up, clk, "the right code")

	if len(writes) != 2 {
		t.Fatalf("%d writes, want one before the check and one after it: %q", len(writes), writes)
	}
	if stepAtFirstWrite != 0 {
		t.Errorf("the code's step was spent, %d, before the first write", stepAtFirstWrite)
	}
	if !strings.Contains(writes[0], "\na 1 0\n") {
		t.Errorf("the first write does not carry the count: %q", writes[0])
	}
	if want := fmt.Sprintf("\na 0 %d\n", uint64(clk.wall.Unix())/30); !strings.Contains(writes[1], want) {
		t.Errorf("the second write does not clear the count and carry the step: %q", writes[1])
	}
	if got := throttleLines(t, dir); len(got) != 1 {
		t.Errorf("file: %q", got)
	}
}

// What dying in the check leaves behind: the try is on the disk, so it was not free.
func TestATryThatDiesInTheCheckIsStillCounted(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := policyFor(factorTOTP)
	real := m.writeThrottleForTest()
	writes := 0
	setThrottleWriter(m, func(path string, data []byte) error {
		writes++
		if writes == 2 {
			return errPowerCut // the process is gone before the success reaches the disk
		}
		return real(path, data)
	})
	mustOpen(t, m, "a", unlockAttempt{Code: codeNow(t, m, "a", clk.wall)}, up, clk, "the right code")
	if got := throttleLines(t, dir); len(got) != 1 || got[0] != "a 1 0" {
		t.Errorf("file after the cut: %q", got)
	}
}

var errPowerCut = errors.New("power cut")

func TestSuccessClearsTheCountOnTheDisk(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 4)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN on the fifth try")
	if got := throttleLines(t, dir); len(got) != 1 || got[0] != "a 0 0" {
		t.Fatalf("file: %q", got)
	}
	m = restart(t, dir, clk)
	fail(t, m, "a", up, clk, 4) // and the free tries are back, across a restart too
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after the free tries came back")
}

func TestSuccessAfterADelayGivesTheFreeTriesBack(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	reach(t, m, "a", up, clk, 8)
	clk.pass(time.Hour)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after the delay")
	fail(t, m, "a", up, clk, 4)
	if st := m.State("a", clk.wall); st.Failures != 4 || !st.LockedOutUntil.IsZero() {
		t.Errorf("after a success: %+v", st)
	}
}

func TestADayOfUptimeResetsTheCount(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	reach(t, m, "a", up, clk, 7)

	clk.pass(24*time.Hour - time.Nanosecond)
	if got := m.State("a", clk.wall).Failures; got != 7 {
		t.Fatalf("failures = %d a nanosecond short of a day, want 7", got)
	}
	clk.pass(time.Nanosecond)
	if got := m.State("a", clk.wall).Failures; got != 0 {
		t.Fatalf("failures = %d after a day of uptime, want 0", got)
	}
	fail(t, m, "a", up, clk, 4) // the free tries are back
	if got := throttleLines(t, dir); len(got) != 1 || got[0] != "a 4 0" {
		t.Errorf("file: %q", got)
	}
}

// A refused try is no counted failure: hammering a delay does not keep the count alive. A counted
// failure is, and it restarts the day.
func TestOnlyACountedFailureRestartsTheDay(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	for i := 0; i < 10; i++ {
		clk.pass(time.Minute)
		mustBeRefused(t, m, "a", wrongPIN, up, clk, "inside the delay")
	}
	clk.pass(24*time.Hour - 10*time.Minute)
	if got := m.State("a", clk.wall).Failures; got != 0 {
		t.Fatalf("refused tries kept the count alive: %d", got)
	}

	fail(t, m, "a", up, clk, 5)
	clk.pass(23 * time.Hour)
	fail(t, m, "a", up, clk, 1)
	clk.pass(23 * time.Hour)
	if got := m.State("a", clk.wall).Failures; got != 6 {
		t.Errorf("a counted failure did not restart the day: failures = %d, want 6", got)
	}
}

func TestTheWallClockCannotDecayTheCount(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	clk.jump(10 * 24 * time.Hour)
	if got := m.State("a", clk.wall).Failures; got != 5 {
		t.Errorf("failures = %d after the clock jumped ten days, want 5", got)
	}
	mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN after the clock jumped")
}

// Uptime is this boot's: a day counted before a reboot is not on the disk, so it starts again.
func TestARestartStartsTheDayAgain(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	clk.pass(23 * time.Hour)
	m = restart(t, dir, clk)
	clk.pass(23 * time.Hour)
	if got := m.StateUnder("a", up, clk.wall).Failures; got != 5 {
		t.Fatalf("failures = %d, want 5: the day restarted with the daemon", got)
	}
	clk.pass(time.Hour)
	if got := m.StateUnder("a", up, clk.wall).Failures; got != 0 {
		t.Errorf("failures = %d a day of uptime after the restart, want 0", got)
	}
}

// A client that stopped trying is forgotten on the disk as well, so the next restart does not
// charge it a delay for tries a day old.
func TestSweepCarriesTheDayToTheDisk(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	clk.pass(23 * time.Hour)
	m.Sweep()
	if got := throttleLines(t, dir); got[0] != "a 5 0" {
		t.Fatalf("a day short: %q", got)
	}
	clk.pass(time.Hour)
	m.Sweep()
	if got := throttleLines(t, dir); got[0] != "a 0 0" {
		t.Fatalf("a day of uptime: %q", got)
	}
	m = restart(t, dir, clk)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after the restart")
}

// A client this process has never met has a day of uptime too.
func TestSweepForgetsAClientThisProcessNeverMet(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	fail(t, m, "a", pinPolicy(), clk, 5)
	m = restart(t, dir, clk)
	clk.pass(24 * time.Hour)
	m.Sweep()
	if got := throttleLines(t, dir); got[0] != "a 0 0" {
		t.Errorf("file: %q", got)
	}
}

func TestSweepWritesNothingWhenNothingChanged(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	fail(t, m, "a", pinPolicy(), clk, 3)
	before, _ := os.Stat(filepath.Join(dir, "throttle"))
	clk.pass(time.Hour)
	m.Sweep()
	after, _ := os.Stat(filepath.Join(dir, "throttle"))
	if !os.SameFile(before, after) {
		t.Error("a sweep with nothing to do replaced the file")
	}
}

func TestARefusalInADelayWritesNothing(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)
	before, _ := os.Stat(filepath.Join(dir, "throttle"))
	writes := 0
	real := m.writeThrottleForTest()
	setThrottleWriter(m, func(path string, data []byte) error { writes++; return real(path, data) })
	for i := 0; i < 50; i++ {
		mustBeRefused(t, m, "a", rightPIN, up, clk, "inside the delay")
	}
	after, _ := os.Stat(filepath.Join(dir, "throttle"))
	if writes != 0 || !os.SameFile(before, after) {
		t.Errorf("%d writes for 50 refusals", writes)
	}
	if st := m.State("a", clk.wall); st.Failures != 5 || st.Refused != 50 {
		t.Errorf("state = %+v, want 5 failures and 50 refused", st)
	}
}

func TestACorruptRecordReadsAsTheLimit(t *testing.T) {
	for name, body := range map[string]string{
		"a count that is no number":   throttleHeader + "a many 0\n",
		"a step that is no number":    throttleHeader + "a 2 soon\n",
		"a negative count":            throttleHeader + "a -1 0\n",
		"a count too large to be one": throttleHeader + "a 99999999999999999999 0\n",
		"a count over the bound":      throttleHeader + "a 2000000000 0\n",
		"a record cut short":          throttleHeader + "a 7\n",
		"a record cut to the name":    throttleHeader + "a\n",
		"too many fields":             throttleHeader + "a 1 2 3\n",
		"a line naming nobody":        throttleHeader + "\x00\x00\x00\n",
		"a name that does not read":   throttleHeader + "%zz 1 0\n",
		"no header at all":            "a",
		"an empty file":               "",
		"a file of zero bytes":        "\x00\x00\x00\x00",
		"another client's line only":  "b 1 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			m, dir := enrolled(t, "4821", "a")
			writeThrottleFixture(t, dir, body)
			clk := &testClock{wall: t0}
			m = restart(t, dir, clk)
			up := pinPolicy()

			mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN against a corrupt record")
			if st := m.StateUnder("a", up, clk.wall); st.Failures != 5 || !st.LockedOutUntil.Equal(clk.wall.Add(15*time.Minute)) {
				t.Errorf("state %+v, want the limit and the first delay, no more", st)
			}
			clk.pass(15 * time.Minute)
			mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after one first delay")
			m = restart(t, dir, clk)
			mustOpen(t, m, "a", rightPIN, up, clk, "the next day's right PIN: the record is good again")
		})
	}
}

func TestAMissingFileReadsAsZero(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	if _, err := os.Stat(filepath.Join(dir, "throttle")); !os.IsNotExist(err) {
		t.Fatalf("a new store has a file: %v", err)
	}
	fail(t, m, "a", up, clk, 4)
	os.Remove(filepath.Join(dir, "throttle"))
	m = restart(t, dir, clk)
	fail(t, m, "a", up, clk, 4)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after the fifth try of a fresh count")
}

// A client whose line is corrupt keeps it, unread, through another client's write: the daemon has
// no count to put there, and dropping it would read as zero.
func TestAnotherClientsWriteKeepsACorruptLine(t *testing.T) {
	m, dir := enrolled(t, "4821", "a", "b")
	writeThrottleFixture(t, dir, throttleHeader+"a 3 77\nb many 0\nc 9 88\n")
	clk := &testClock{wall: t0}
	m = restart(t, dir, clk)
	fail(t, m, "a", pinPolicy(), clk, 1)
	want := []string{"a 4 77", "b many 0", "c 9 88"}
	if got := throttleLines(t, dir); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("file %q, want %q", got, want)
	}
}

// A record that goes bad under a running daemon never lowers what the daemon counted.
func TestARecordThatGoesBadRaisesAndNeverLowers(t *testing.T) {
	m, dir := enrolled(t, "4821", "a", "b")
	clk := useClock(m)
	up := pinPolicy()
	reach(t, m, "a", up, clk, 7)
	fail(t, m, "b", up, clk, 2)
	writeThrottleFixture(t, dir, throttleHeader+"a 7 x\nb 2 x\n")
	if got := m.State("a", clk.wall).Failures; got != 7 {
		t.Errorf("a: failures = %d, want 7: a bad record must not lower a count", got)
	}
	st := m.StateUnder("b", up, clk.wall)
	if st.Failures != 5 || !st.LockedOutUntil.Equal(clk.wall.Add(15*time.Minute)) {
		t.Errorf("b: %+v, want the limit and a delay from now", st)
	}
}

func fullDisk(string, []byte) error { return syscall.ENOSPC }

func TestAFullDiskKeepsWorkingFromMemory(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 2)
	setThrottleWriter(m, fullDisk)

	fail(t, m, "a", up, clk, 3)
	if m.ThrottlePersisted() {
		t.Fatal("the store says the count is on the disk")
	}
	if got := throttleLines(t, dir); got[0] != "a 2 0" {
		t.Fatalf("the file moved: %q", got)
	}
	// The delay holds from memory, and the owner is not refused because of the disk.
	mustBeRefused(t, m, "a", rightPIN, up, clk, "inside a delay counted in memory")
	if st := m.State("a", clk.wall); st.Failures != 5 {
		t.Errorf("failures = %d, want 5 from memory", st.Failures)
	}
	clk.pass(15 * time.Minute)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN with the disk still full")
	if st := m.State("a", clk.wall); st.Failures != 0 {
		t.Errorf("failures = %d, want 0 after a success on a full disk", st.Failures)
	}
}

func TestAFullDiskCatchesUpWhenItCanWriteAgain(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	real := m.writeThrottleForTest()
	fail(t, m, "a", up, clk, 1)
	setThrottleWriter(m, fullDisk)
	fail(t, m, "a", up, clk, 2)
	setThrottleWriter(m, real)
	m.Sweep()
	if !m.ThrottlePersisted() {
		t.Error("the store still says the count is not on the disk")
	}
	if got := throttleLines(t, dir); got[0] != "a 3 0" {
		t.Errorf("the sweep did not catch up: %q", got)
	}
}

// The real thing: a directory the daemon cannot write in.
func TestAReadOnlyDirectoryDoesNotLockTheOwnerOut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through the mode bits")
	}
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 1)
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	fail(t, m, "a", up, clk, 3)
	if m.ThrottlePersisted() {
		t.Error("a read-only directory reports the count as saved")
	}
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN on a read-only directory")
}

// A file that cannot be read is not replaced: what it holds for the other clients would go.
func TestAnUnreadableFileIsNotReplaced(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	os.Remove(filepath.Join(dir, "throttle"))
	if err := os.Mkdir(filepath.Join(dir, "throttle"), 0o700); err != nil {
		t.Fatal(err)
	}
	clk := &testClock{wall: t0}
	m = restart(t, dir, clk)
	up := pinPolicy()
	mustBeRefused(t, m, "a", rightPIN, up, clk, "the right PIN against a file that cannot be read")
	clk.pass(15 * time.Minute)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after one delay")
	if m.ThrottlePersisted() {
		t.Error("a file that cannot be read reports the count as saved")
	}
	if st, err := os.Stat(filepath.Join(dir, "throttle")); err != nil || !st.IsDir() {
		t.Error("the file that could not be read was replaced")
	}
}

// The same for a file the mode bits keep out: a replacement would succeed, and it must not be made.
func TestAFileThatCannotBeReadIsNotReplaced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through the mode bits")
	}
	m, dir := enrolled(t, "4821", "a", "b")
	path := filepath.Join(dir, "throttle")
	writeThrottleFixture(t, dir, throttleHeader+"b 9 0\n")
	os.Chmod(path, 0)
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	clk := &testClock{wall: t0}
	m = restart(t, dir, clk)
	clk.pass(15 * time.Minute)
	mustOpen(t, m, "a", rightPIN, pinPolicy(), clk, "the right PIN after one delay")
	if m.ThrottlePersisted() {
		t.Error("the store says the count is on the disk")
	}
	os.Chmod(path, 0o600)
	if got := throttleLines(t, dir); len(got) != 1 || got[0] != "b 9 0" {
		t.Errorf("the file was replaced, and with it what it held for b: %q", got)
	}
}

// `pair` takes any name. A name that would break the line must not lose its own count, and must not
// leave a line that reads as nobody's, which every other client would then read as the limit.
func TestAClientNameThatCouldBreakTheFileKeepsItsCount(t *testing.T) {
	for _, name := range []string{"my laptop", "#hash", "a\nb", "100%", "tab\tname", "ünï"} {
		m, dir := enrolled(t, "4821", "other")
		clk := useClock(m)
		up := pinPolicy()
		m.pins.Set(name, "4821") // the store takes what the CLI would refuse; the daemon must cope
		for i := 0; i < 3; i++ {
			m.Attempt(name, wrongPIN, up, clk.wall)
		}
		m = restart(t, dir, clk)
		if got := m.StateUnder(name, up, clk.wall).Failures; got != 3 {
			t.Errorf("%q: failures = %d after a restart, want 3\n%s", name, got, readFile(t, filepath.Join(dir, "throttle")))
		}
		if st := m.StateUnder("other", up, clk.wall); st.Failures != 0 || !st.LockedOutUntil.IsZero() {
			t.Errorf("%q: another client reads %+v", name, st)
		}
		if got := len(throttleLines(t, dir)); got != 1 {
			t.Errorf("%q: %d lines for one client", name, got)
		}
	}
}

// A line that names nobody may have been anyone's, so it stays, and everyone it might have been
// keeps reading as the limit until a success or a reset writes a line of their own.
func TestAJunkLineStaysThroughAWrite(t *testing.T) {
	m, dir := enrolled(t, "4821", "a", "b")
	writeThrottleFixture(t, dir, throttleHeader+"garbled\n")
	clk := &testClock{wall: t0}
	m = restart(t, dir, clk)
	up := pinPolicy()
	clk.pass(15 * time.Minute)
	mustOpen(t, m, "a", rightPIN, up, clk, "a's right PIN after one delay")
	m = restart(t, dir, clk)
	mustOpen(t, m, "a", rightPIN, up, clk, "a, which has a line of its own now")
	mustBeRefused(t, m, "b", rightPIN, up, clk, "b, which still has none")
}

// The default writer is the atomic one: the store itself syncs what it writes.
func TestTheStoreSyncsWhatItWrites(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	real := syncFile
	t.Cleanup(func() { syncFile = real })
	n := 0
	syncFile = func(f *os.File) error { n++; return real(f) }
	fail(t, m, "a", pinPolicy(), clk, 1)
	if n != 2 {
		t.Errorf("%d syncs for one write, want the file and the directory", n)
	}
}

// A step can be all that is waiting for the disk: a success leaves a count of zero, the same as
// the file says, and the code it spent must still reach the file.
func TestASpentStepCatchesUpAfterAFullDisk(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	real := m.writeThrottleForTest()
	setThrottleWriter(m, fullDisk)
	code := codeNow(t, m, "a", clk.wall)
	mustOpen(t, m, "a", unlockAttempt{Code: code}, policyFor(factorTOTP), clk, "the code on a full disk")
	setThrottleWriter(m, real)
	m.Sweep()
	if want := fmt.Sprintf("a 0 %d", uint64(clk.wall.Unix())/30); throttleLines(t, dir)[0] != want {
		t.Errorf("file %q, want %q", throttleLines(t, dir), want)
	}
}

func TestParallelAttemptsCannotSlipUnderTheLimit(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Attempt("a", wrongPIN, up, clk.wall)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	checked, refused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			t.Fatal("a wrong PIN unlocked")
		case strings.Contains(err.Error(), "locked out"):
			refused++
		default:
			checked++
		}
	}
	if checked != 5 || refused != 27 {
		t.Errorf("%d checked and %d refused, want 5 and 27", checked, refused)
	}
	if got := throttleLines(t, dir); got[0] != "a 5 0" {
		t.Errorf("file: %q", got)
	}
}

func TestACodeCannotBeReplayedAfterARestart(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := policyFor(factorTOTP)
	code := codeNow(t, m, "a", clk.wall)
	mustOpen(t, m, "a", unlockAttempt{Code: code}, up, clk, "the first use of the code")
	m = restart(t, dir, clk)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, up, clk.wall); err == nil || err.Error() != "code already used" {
		t.Errorf("the code after a restart: %v, want it refused as used", err)
	}
	clk.pass(30 * time.Second)
	mustOpen(t, m, "a", unlockAttempt{Code: codeNow(t, m, "a", clk.wall)}, up, clk, "the next code")
}

// Verify spends the step as Attempt does, and an approval's code must stay spent the same way.
func TestAnApprovalsCodeStaysSpentAfterARestart(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := policyFor(factorTOTP)
	code := codeNow(t, m, "a", clk.wall)
	if err := m.Verify("a", unlockAttempt{Code: code}, up, clk.wall); err != nil {
		t.Fatal(err)
	}
	m = restart(t, dir, clk)
	if err := m.Verify("a", unlockAttempt{Code: code}, up, clk.wall); err == nil {
		t.Error("an approval's code was accepted again after a restart")
	}
}

func TestRestartKeepsTheStepSpentByActivate(t *testing.T) {
	m, dir := newMFA(t)
	clk := useClock(m)
	if _, _, err := m.EnrolPending("a", "openwrt-mcp", "r"); err != nil {
		t.Fatal(err)
	}
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	ctr := uint64(clk.wall.Unix()) / 30
	code, _ := totpAt(pend["a"], ctr)
	if err := m.Activate("a", code, clk.wall); err != nil {
		t.Fatal(err)
	}
	m = restart(t, dir, clk)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, policyFor(factorTOTP), clk.wall); err == nil {
		t.Error("a daemon started after `mfa activate` accepted the code that activated the secret")
	}
}

func TestResetFromTheCLIReachesARunningDaemon(t *testing.T) {
	daemon, dir := enrolled(t, "4821", "a", "b")
	clk := useClock(daemon)
	up := pinPolicy()
	reach(t, daemon, "a", up, clk, 7)
	fail(t, daemon, "b", up, clk, 2)

	cli, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runMFAReset(&out, cli, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "7") || !strings.Contains(out.String(), `"a"`) {
		t.Errorf("the reset says %q", out.String())
	}
	mustOpen(t, daemon, "a", rightPIN, up, clk, "the right PIN straight after `mfa reset`")
	// The other client's count is not the reset's to touch, whichever process writes next.
	if got := daemon.State("b", clk.wall).Failures; got != 2 {
		t.Errorf("b: failures = %d, want 2", got)
	}
	if got := throttleLines(t, dir); got[0] != "a 0 0" || got[1] != "b 2 0" {
		t.Errorf("file: %q", got)
	}
}

// The reset must survive another client's write: the daemon's memory of the old count is exactly
// what must not go back to the disk.
func TestAResetIsNotUndoneByTheNextWrite(t *testing.T) {
	daemon, dir := enrolled(t, "4821", "a", "b")
	clk := useClock(daemon)
	up := pinPolicy()
	fail(t, daemon, "a", up, clk, 5)
	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	if _, err := cli.ResetThrottle("a"); err != nil {
		t.Fatal(err)
	}
	fail(t, daemon, "b", up, clk, 1)
	if got := throttleLines(t, dir); got[0] != "a 0 0" || got[1] != "b 1 0" {
		t.Errorf("the next write undid the reset: %q", got)
	}
}

func TestResetKeepsTheSpentStep(t *testing.T) {
	daemon, dir := enrolled(t, "4821", "a")
	clk := useClock(daemon)
	up := policyFor(factorTOTP)
	code := codeNow(t, daemon, "a", clk.wall)
	mustOpen(t, daemon, "a", unlockAttempt{Code: code}, up, clk, "the code")
	daemon.Lock("a")
	if _, err := daemon.Attempt("a", unlockAttempt{Code: "000000"}, up, clk.wall); err == nil {
		t.Fatal("a wrong code unlocked")
	}
	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	if _, err := cli.ResetThrottle("a"); err != nil {
		t.Fatal(err)
	}
	if got := throttleLines(t, dir)[0]; got != fmt.Sprintf("a 0 %d", uint64(clk.wall.Unix())/30) {
		t.Errorf("the reset lost the step: %q", got)
	}
	m := restart(t, dir, clk)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, up, clk.wall); err == nil {
		t.Error("a reset let a spent code back in")
	}
}

func TestResetHealsACorruptRecord(t *testing.T) {
	daemon, dir := enrolled(t, "4821", "a")
	writeThrottleFixture(t, dir, throttleHeader+"a many 0\n")
	clk := &testClock{wall: t0}
	daemon = restart(t, dir, clk)
	up := pinPolicy()
	mustBeRefused(t, daemon, "a", rightPIN, up, clk, "a corrupt record")

	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	if _, err := cli.ResetThrottle("a"); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, daemon, "a", rightPIN, up, clk, "the right PIN after the reset")
}

// A success stands against a record the disk will not let go of: the limit is charged once, not
// after every unlock.
func TestACorruptRecordOnAFullDiskIsChargedOnce(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	writeThrottleFixture(t, dir, throttleHeader+"a many 0\n")
	clk := &testClock{wall: t0}
	m = restart(t, dir, clk)
	setThrottleWriter(m, fullDisk)
	up := pinPolicy()
	clk.pass(15 * time.Minute)
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN after the first delay")
	mustOpen(t, m, "a", rightPIN, up, clk, "the right PIN again, with the record still corrupt on the disk")
}

func TestResetSaysWhenThereIsNothingToReset(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	var out bytes.Buffer
	if err := runMFAReset(&out, m, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing to reset") {
		t.Errorf("it says %q", out.String())
	}
	for _, args := range [][]string{nil, {"a", "b"}} {
		if err := runMFAReset(&out, m, args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if err := runMFAReset(&out, m, []string{"two words"}); err == nil {
		t.Error("a client name with a space was accepted")
	}
}

func TestResetReportsADiskThatWillNotTakeIt(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	clk := useClock(m)
	fail(t, m, "a", pinPolicy(), clk, 1)
	setThrottleWriter(m, fullDisk)
	var out bytes.Buffer
	if err := runMFAReset(&out, m, []string{"a"}); err == nil {
		t.Error("a reset that did not reach the disk reported success")
	}
}

func TestCLIMFAReset(t *testing.T) {
	c := newCLI(t)
	if err := os.MkdirAll(c.state, 0o700); err != nil {
		t.Fatal(err)
	}
	writeThrottleFixture(t, c.state, throttleHeader+"claude 7 123\n")
	out, errOut, code := c.run("", "mfa", "reset", "claude")
	if code != 0 || !strings.Contains(out, "7 failed tries") {
		t.Fatalf("mfa reset: exit %d, %q %q", code, out, errOut)
	}
	if got := throttleLines(t, c.state); len(got) != 1 || got[0] != "claude 0 123" {
		t.Errorf("file: %q", got)
	}
	if _, _, code := c.run("", "mfa", "reset"); code == 0 {
		t.Error("mfa reset with no client succeeded")
	}
}

// Rotating a credential is the owner's other way out, and the daemon may not be running to see it.
func TestRotatingAPINWithTheDaemonStoppedClearsTheRecord(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := pinPolicy()
	fail(t, m, "a", up, clk, 5)

	var out bytes.Buffer
	if err := runPIN(&out, strings.NewReader("5926\n"), dir, []string{"set", "a"}); err != nil {
		t.Fatal(err)
	}
	m = restart(t, dir, clk)
	mustOpen(t, m, "a", unlockAttempt{PIN: "5926"}, up, clk, "the new PIN after a restart")
}

func TestRotatingATOTPSecretWithTheDaemonStoppedClearsTheRecord(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	up := policyFor(factorTOTP)
	code := codeNow(t, m, "a", clk.wall)
	mustOpen(t, m, "a", unlockAttempt{Code: code}, up, clk, "a code under the old secret")
	fail(t, m, "a", up, clk, 5)

	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	if _, _, err := cli.Enrol("a", "openwrt-mcp", "r"); err != nil {
		t.Fatal(err)
	}
	if got := throttleLines(t, dir)[0]; got != "a 0 0" {
		t.Errorf("a rotated secret kept its record: %q", got)
	}
	m = restart(t, dir, clk)
	mustOpen(t, m, "a", unlockAttempt{Code: codeNow(t, m, "a", clk.wall)}, up, clk, "a code under the new secret, in the same step")
}

func TestLockLeavesTheCountOnTheDisk(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	clk := useClock(m)
	fail(t, m, "a", pinPolicy(), clk, 2)
	m.Lock("a")
	if got := throttleLines(t, dir)[0]; got != "a 2 0" {
		t.Errorf("file: %q", got)
	}
}

// ---------------------------------------------------------------- atomic writes

func TestAtomicWriteSyncsTheFileThenTheDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "throttle")
	writeFile(t, path, "old")
	var synced []string
	real := syncFile
	t.Cleanup(func() { syncFile = real })
	syncFile = func(f *os.File) error {
		// The file must be on the disk under its sidecar name, and the name it replaces untouched,
		// when it is synced; the directory is synced once the rename has been made.
		synced = append(synced, filepath.Base(f.Name())+"="+readFile(t, path))
		return real(f)
	}
	if err := atomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 2 || !strings.HasPrefix(synced[0], "throttle.new.") || !strings.HasSuffix(synced[0], "=old") ||
		synced[1] != filepath.Base(dir)+"=new" {
		t.Errorf("synced %q, want the sidecar with the old file in place, then the directory with the new one", synced)
	}
}

func TestAtomicWriteLeavesTheOldFileOnAFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "throttle")
	writeFile(t, path, "old")
	real := syncFile
	t.Cleanup(func() { syncFile = real })
	syncFile = func(*os.File) error { return syscall.EIO }
	if err := atomicWriteFile(path, []byte("new"), 0o600); !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want EIO", err)
	}
	if got := readFile(t, path); got != "old" {
		t.Errorf("the file reads %q", got)
	}
	left, _ := filepath.Glob(path + ".new*")
	if len(left) != 0 {
		t.Errorf("sidecars left behind: %q", left)
	}
}

func TestAtomicWriteReportsADirectoryThatCannotBeSynced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "throttle")
	real := syncFile
	t.Cleanup(func() { syncFile = real })
	n := 0
	syncFile = func(f *os.File) error {
		if n++; n == 2 {
			return syscall.EIO
		}
		return real(f)
	}
	if err := atomicWriteFile(path, []byte("new"), 0o600); !errors.Is(err, syscall.EIO) {
		t.Errorf("err = %v, want the directory's EIO", err)
	}
}

func TestAtomicWriteTightensAStaleSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "throttle")
	stale := fmt.Sprintf("%s.new.%d", path, os.Getpid())
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
}

func TestAtomicWriteReportsWhatStopsIt(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	writeFile(t, notADir, "x")
	if err := atomicWriteFile(filepath.Join(notADir, "throttle"), []byte("new"), 0o600); err == nil {
		t.Error("a path under a file was written")
	}
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(target, []byte("new"), 0o600); err == nil {
		t.Error("a directory was replaced")
	}
	if left, _ := filepath.Glob(target + ".new*"); len(left) != 0 {
		t.Errorf("sidecars left behind: %q", left)
	}
}

func TestAtomicWriteMakesItsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "throttle")
	if err := atomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Dir(path)); st.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", st.Mode().Perm())
	}
}

// ---------------------------------------------------------------- the common PINs

func TestPinSetRefusesTheMostCommonPINs(t *testing.T) {
	for _, pin := range []string{"1234", "1111", "0000", "1212", "7777", "4321", "123456", "000000", "12345678"} {
		state := t.TempDir()
		var out bytes.Buffer
		err := runPIN(&out, strings.NewReader(pin+"\n"), state, []string{"set", "a"})
		if err == nil {
			t.Errorf("%s: accepted", pin)
			continue
		}
		if !strings.Contains(err.Error(), "most common") || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: not one clear line: %q", pin, err)
		}
		if strings.Contains(err.Error(), pin) {
			t.Errorf("%s: the refusal repeats the PIN: %q", pin, err)
		}
		if _, statErr := os.Stat(filepath.Join(state, "pin")); !os.IsNotExist(statErr) {
			t.Errorf("%s: a file was written", pin)
		}
	}
}

func TestPinSetAcceptsAPINOffTheList(t *testing.T) {
	for _, pin := range []string{"4821", "5926", "73918246", "1235", "0001"} {
		var out bytes.Buffer
		if err := runPIN(&out, strings.NewReader(pin+"\n"), t.TempDir(), []string{"set", "a"}); err != nil {
			t.Errorf("%s: %v", pin, err)
		}
	}
}

// The list stops a new weak PIN. A PIN already on file keeps working: refusing it would lock the
// owner out of the router by an upgrade.
func TestAWeakPINAlreadyOnFileKeepsWorking(t *testing.T) {
	m, _ := enrolled(t, "1234", "a")
	clk := useClock(m)
	mustOpen(t, m, "a", unlockAttempt{PIN: "1234"}, pinPolicy(), clk, "a PIN set before the list existed")
}

func TestCommonPINsAreAllValidPINs(t *testing.T) {
	if len(commonPINs) == 0 || len(commonPINs) > 64 {
		t.Fatalf("the list has %d entries, and it is meant to be short", len(commonPINs))
	}
	for pin := range commonPINs {
		if !regexp.MustCompile(`^[0-9]{4,8}$`).MatchString(pin) {
			t.Errorf("%q could never be set", pin)
		}
	}
}
