package main

import "time"

// The seams the tests reach through, in one place. On the code before the throttle these three
// were stubs, which is how every new test was run against it and seen red.

func setStoreClock(m *MFAStore, f func() time.Duration) { m.mono = f }

func setAuditClock(a *Auditor, f func() time.Duration) { a.mono = f }

func setThrottleWriter(m *MFAStore, f func(path string, data []byte) error) { m.writeThrottle = f }

// writeThrottleForTest is the store's own writer, to wrap.
func (m *MFAStore) writeThrottleForTest() func(path string, data []byte) error {
	return m.writeThrottle
}
