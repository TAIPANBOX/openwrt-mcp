package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The guess throttle of the second factor.
//
// A failed try costs time, and the cost grows. mfa_max_failures tries are free; the failure that
// reaches that limit costs a wait of mfa_lockout, the next one twice that, and so on up to one try
// an hour. There is no overall cap: a lockout that never ends would outlive the attack that caused
// it, and on a home router with one owner that means a trip home (docs/security.md has the reasons
// and the standard this departs from).
//
// What is kept where is the point of this file, and nothing here may read the wall clock:
//
//   - The disk holds a failure count and the last accepted TOTP step per client, and no time at
//     all. A router with no battery boots with an old clock and ntpd then jumps it, so a stored
//     "not before" would be skipped by a jump forward, stretched for years by a wrong clock, and
//     reset by a forged time server. A count has none of those problems.
//   - The moment of the next try lives in memory, on the monotonic clock, as the moment of the
//     last counted failure. The wait is derived from it and from the count.
//   - A process that starts knows the count and not the moment, so it treats its own start as the
//     moment of the last failure. A client at or above the limit therefore begins a fresh delay:
//     neither a restart nor a reboot gets round one, and neither costs more than one more delay.
//
// The file is read on every try, which is what lets `openwrt-mcp mfa reset`, a separate process,
// reach a running daemon with no channel into it. Memory stands while the file still says what it
// said when last seen, so a failed write (the overlay is full) leaves the daemon counting in memory
// and never turns a full disk into a refusal.

const (
	// throttleCeiling is the longest wait, unless mfa_lockout itself asks for a longer one.
	throttleCeiling = time.Hour
	// throttleDecay is how long a client must go without a counted failure, in uptime, for its
	// count to be forgotten. A pause costs a guesser 24 tries and hands back the free ones.
	throttleDecay = 24 * time.Hour
	// throttleMaxCount is the largest count the file may claim; anything above it is corrupt.
	throttleMaxCount = 1 << 30
	throttleFileMode = 0o600

	throttleHeader = "# openwrt-mcp second-factor throttle, format 1. Do not edit; use: openwrt-mcp mfa reset <client>\n"
	// throttleNoHeader stands in the file for what a corrupt file cannot say: which clients it
	// held. It names nobody, so every client without a good line of its own reads as the limit.
	throttleNoHeader = "unreadable-before-this-line"
	// throttleUnread is onDisk when the file holds no count that can be believed.
	throttleUnread = -1
)

// delayAfter is how long a client that has failed n times in a row waits for its next try. The
// configured limit and delay keep their meaning: they are the first threshold and the first delay.
func delayAfter(n int, up unlockPolicy) time.Duration {
	if n < up.MaxFailures {
		return 0
	}
	ceiling := max(throttleCeiling, up.Lockout)
	d := up.Lockout
	for i := up.MaxFailures; i < n && d < ceiling; i++ {
		d *= 2
	}
	return min(d, ceiling)
}

// throttleEntry is one client as this process counts it.
type throttleEntry struct {
	fails    int           // consecutive failed tries
	onDisk   int           // what the file said when last read or written; behind fails while a write fails
	lastFail time.Duration // monotonic: the last counted failure, or 0, the start of this process
	refused  int           // tries refused inside the current delay
	up       unlockPolicy  // the limit and delay last asked for, for a report that names none
}

// wait is how long the client must still wait at mono, or nothing.
func (e *throttleEntry) wait(up unlockPolicy, mono time.Duration) time.Duration {
	return e.lastFail + delayAfter(e.fails, up) - mono
}

// merge folds the file into the entry. The file wins when it changed since it was last seen: that
// is `mfa reset`. A record that cannot be believed never lowers a count, and raises one to the
// limit: zero would be a way round the throttle, more would punish the owner for a bad sector.
func (e *throttleEntry) merge(client string, tf throttleFile, mono time.Duration) {
	n, believed := tf.count(client)
	switch {
	case !believed:
		if e.onDisk == throttleUnread {
			return // already answered for, and what happened since (a success, a reset) stands
		}
		e.onDisk = throttleUnread
		if e.fails < e.up.MaxFailures {
			log.Printf("openwrt-mcp: the throttle record of %q cannot be read; it counts as the limit", client)
			e.fails, e.lastFail = e.up.MaxFailures, mono
		}
	case n != e.onDisk:
		e.fails, e.onDisk, e.refused = n, n, 0
	}
}

// throttleRecord is one client's line.
type throttleRecord struct {
	fails int
	step  uint64
	bad   bool
	line  string
}

// throttleFile is the file as it stands. A line that does not read as a client's record stays in
// junk and is written back as it was: it may have been anyone's, so it is not ours to drop.
type throttleFile struct {
	recs       map[string]throttleRecord
	junk       []string
	unreadable bool
}

func (m *MFAStore) throttlePath() string { return filepath.Join(filepath.Dir(m.path), "throttle") }

func readThrottleFile(path string) throttleFile {
	tf := throttleFile{recs: map[string]throttleRecord{}}
	b, err := os.ReadFile(path)
	if err != nil {
		tf.unreadable = !os.IsNotExist(err)
		return tf
	}
	if !strings.HasPrefix(string(b), "# openwrt-mcp second-factor throttle") {
		tf.junk = append(tf.junk, throttleNoHeader)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			tf.junk = append(tf.junk, line)
			continue
		}
		client, err := url.PathUnescape(f[0])
		if err != nil {
			tf.junk = append(tf.junk, line)
			continue
		}
		rec := throttleRecord{line: line}
		fails, errFails := strconv.Atoi(f[1])
		step, errStep := strconv.ParseUint(f[2], 10, 64)
		if errFails != nil || errStep != nil || fails < 0 || fails > throttleMaxCount {
			rec.bad = true
		} else {
			rec.fails, rec.step = fails, step
		}
		tf.recs[client] = rec
	}
	return tf
}

// count is what the file says of a client, and whether it can be believed. A missing file, and a
// sound file with no line for the client, are zero: that is a new install.
func (tf throttleFile) count(client string) (int, bool) {
	rec, on := tf.recs[client]
	switch {
	case on && !rec.bad:
		return rec.fails, true
	case on, tf.unreadable, len(tf.junk) > 0:
		return 0, false
	}
	return 0, true
}

// syncThrottleLocked reads the file and folds it into every client this process knows. Callers
// hold m.mu.
func (m *MFAStore) syncThrottleLocked(mono time.Duration) throttleFile {
	tf := readThrottleFile(m.throttlePath())
	for client, e := range m.thr {
		e.merge(client, tf, mono)
	}
	return tf
}

// entryLocked is the client's entry, made from the file on first sight, with a day of uptime
// without a counted failure forgotten. Forgotten in memory: the next write carries it to the disk.
// Callers hold m.mu.
func (m *MFAStore) entryLocked(client string, up unlockPolicy, tf throttleFile, mono time.Duration) *throttleEntry {
	e := m.thr[client]
	if e == nil {
		e = &throttleEntry{up: up}
		m.thr[client] = e
		e.merge(client, tf, 0)
	}
	e.up = up
	e.decay(mono)
	return e
}

func (e *throttleEntry) decay(mono time.Duration) {
	if e.fails > 0 && mono-e.lastFail >= throttleDecay {
		e.fails, e.refused = 0, 0
	}
}

// saveThrottleLocked writes every count this process holds, and keeps the lines of the clients it
// has not met as they are. A failed write is not an error to the caller's caller: the count stands
// in memory, and the next write, or the daemon's sweep, tries again. Callers hold m.mu.
func (m *MFAStore) saveThrottleLocked(mono time.Duration) error {
	tf := m.syncThrottleLocked(mono)
	if tf.unreadable {
		// What it holds for the other clients cannot be kept, so it is not replaced.
		err := fmt.Errorf("%s cannot be read", m.throttlePath())
		m.noteThrottleSaved(err)
		return err
	}
	lines := make(map[string]string, len(tf.recs)+len(m.thr))
	for client, rec := range tf.recs {
		lines[client] = rec.line
	}
	for client, e := range m.thr {
		// `pair` takes any name, so the name is escaped: a space or a leading # would make a line
		// that reads as nobody's, and the record of a client that can be tried must always read back.
		lines[client] = fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, m.lastCtr[client])
	}
	clients := make([]string, 0, len(lines))
	for client := range lines {
		clients = append(clients, client)
	}
	sortStrings(clients)
	var b strings.Builder
	b.WriteString(throttleHeader)
	for _, client := range clients {
		b.WriteString(lines[client] + "\n")
	}
	for _, line := range tf.junk {
		b.WriteString(line + "\n")
	}
	err := m.writeThrottle(m.throttlePath(), []byte(b.String()))
	if err == nil {
		for _, e := range m.thr {
			e.onDisk = e.fails
		}
	}
	m.noteThrottleSaved(err)
	return err
}

// noteThrottleSaved says so once when the disk stops taking the count, and once when it starts
// again, rather than on every try.
func (m *MFAStore) noteThrottleSaved(err error) {
	switch was := m.unsaved.Swap(err != nil); {
	case err != nil && !was:
		log.Printf("openwrt-mcp: the second-factor throttle is not reaching the disk (%v); counting in memory", err)
	case err == nil && was:
		log.Printf("openwrt-mcp: the second-factor throttle is reaching the disk again")
	}
}

// clearThrottleLocked drops what a client's earlier credentials cost it, step included: a new
// credential starts clean. Nothing is written for a client with nothing on record. Callers hold
// m.mu.
func (m *MFAStore) clearThrottleLocked(client string) {
	mono := m.mono()
	tf := m.syncThrottleLocked(mono)
	_, onRecord := tf.recs[client]
	if m.thr[client] == nil && !onRecord && len(tf.junk) == 0 {
		return
	}
	e := m.entryLocked(client, m.policyLocked(client), tf, mono)
	e.fails, e.lastFail, e.refused = 0, 0, 0
	_ = m.saveThrottleLocked(mono)
}

// policyLocked is the limit and delay last asked for on this client, or the defaults.
func (m *MFAStore) policyLocked(client string) unlockPolicy {
	if e := m.thr[client]; e != nil {
		return e.up
	}
	return unlockPolicy{}.withDefaults()
}

// ResetThrottle clears a client's failure count and reports what it was. The last accepted step
// stays, so a reset is no way to replay a code. It is reached from the CLI and from nothing else:
// a client that could reset its own count would have no throttle (scripts/gate-throttle.sh).
func (m *MFAStore) ResetThrottle(client string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mono := m.mono()
	tf := m.syncThrottleLocked(mono)
	e := m.entryLocked(client, m.policyLocked(client), tf, mono)
	was := e.fails
	if was == 0 {
		return 0, nil
	}
	e.fails, e.lastFail, e.refused = 0, 0, 0
	return was, m.saveThrottleLocked(mono)
}

// Forget is what a rotated credential does to a client, for the commands that rotate one outside
// the daemon: a daemon that is not running is not there to notice.
func (m *MFAStore) Forget(client string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forgetLocked(client)
}

// RecordedFailures is the count on the disk, as a process other than the daemon can know it. A
// record that cannot be believed reads as the limit, as it does for the daemon.
func (m *MFAStore) RecordedFailures(client string, up unlockPolicy) int {
	n, believed := readThrottleFile(m.throttlePath()).count(client)
	if !believed {
		return up.MaxFailures
	}
	return n
}

// ThrottlePersisted says whether the last write reached the disk. It takes no lock: /health asks,
// and a slow PIN check holds m.mu for as long as a health probe is willing to wait.
func (m *MFAStore) ThrottlePersisted() bool { return !m.unsaved.Load() }

// Sweep is the daemon's minute: a day of uptime is forgotten on the disk too, so a client that
// stopped trying does not meet a delay after the next restart, and a write that failed is tried
// again. It writes only when something changed.
func (m *MFAStore) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	mono := m.mono()
	tf := m.syncThrottleLocked(mono)
	for client, rec := range tf.recs {
		if !rec.bad && rec.fails > 0 && m.thr[client] == nil {
			m.entryLocked(client, m.policyLocked(client), tf, mono)
		}
	}
	changed := m.unsaved.Load()
	for _, e := range m.thr {
		e.decay(mono)
		if e.onDisk != throttleUnread && e.fails != e.onDisk {
			changed = true
		}
	}
	if changed {
		_ = m.saveThrottleLocked(mono)
	}
}

// syncFile is the fsync of atomicWriteFile. A variable only so a test can watch the order and make
// one fail.
var syncFile = func(f *os.File) error { return f.Sync() }

// atomicWriteFile replaces path so that a power cut leaves the old file or the new one, never half
// of one, and so that the new name itself survives: the data is synced before the rename, the
// directory after it. The sidecar carries the pid because the CLI and the daemon may both write.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.new.%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // gone already after the rename
	err = f.Chmod(mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = syncFile(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return syncFile(d)
}
