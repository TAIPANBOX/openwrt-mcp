package main

import (
	"time"
)

// testClock is the two clocks of a router, apart. mono is what the daemon's monotonic clock reads,
// wall what the clock on the wall says: time passing moves both, ntpd stepping the clock or a
// reboot with no battery moves only the second, which is the difference the throttle lives on.
type testClock struct {
	mono time.Duration
	wall time.Time
}

func (c *testClock) now() time.Duration { return c.mono }

// set puts the monotonic clock at d and the wall clock at t0 plus d.
func (c *testClock) set(d time.Duration) { c.mono, c.wall = d, t0.Add(d) }

// pass is time passing.
func (c *testClock) pass(d time.Duration) { c.mono, c.wall = c.mono+d, c.wall.Add(d) }

// jump is the wall clock stepping with no time passing.
func (c *testClock) jump(d time.Duration) { c.wall = c.wall.Add(d) }

// useClock puts a store on a clock that starts at t0.
func useClock(m *MFAStore) *testClock {
	c := &testClock{wall: t0}
	setStoreClock(m, c.now)
	return c
}

// useServerClock puts a daemon, its store and its audit log, on one clock.
func useServerClock(s *Server) *testClock {
	c := &testClock{wall: time.Now()}
	setStoreClock(s.mfa, c.now)
	setAuditClock(s.audit, c.now)
	return c
}
