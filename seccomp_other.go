//go:build !(linux && (amd64 || arm64))

package main

// The filter is off where no real run of the daemon stands behind the list: a list that is wrong
// on a rare path is a daemon that dies on a router.
func confineSeccomp() (int, error) { return 0, errNoSeccomp }
