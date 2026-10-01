package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const mfaEnrolUsage = "usage: openwrt-mcp mfa enrol <client> [device-label] [--qr] [--json] [--pending]\n" +
	"  the label names this router in your authenticator; defaults to the hostname\n" +
	"  --qr       also draw the QR code in the terminal\n" +
	"  --json     print one JSON object {client, uri, secret, qr_png_base64} and nothing else\n" +
	"  --pending  store the secret apart; it takes effect only after: openwrt-mcp mfa activate <client> <code>"

// enrolPNGSize is the side of the PNG a web page gets: big enough to scan off a screen.
const enrolPNGSize = 256

// runMFAEnrol implements `mfa enrol`. Flags may sit anywhere among the arguments. With no
// flag the output is what it has always been, byte for byte, so nothing that reads it
// changes underneath anyone.
func runMFAEnrol(out io.Writer, ms *MFAStore, statePath string, args []string) error {
	var qr, asJSON, pending bool
	var pos []string
	for _, a := range args {
		switch {
		case a == "--qr":
			qr = true
		case a == "--json":
			asJSON = true
		case a == "--pending":
			pending = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown option %q\n%s", a, mfaEnrolUsage)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) < 1 || len(pos) > 2 {
		return fmt.Errorf("%s", mfaEnrolUsage)
	}
	client, device := pos[0], ""
	if len(pos) == 2 {
		device = pos[1]
	}
	if err := validClientName(client); err != nil {
		return err
	}

	enrol := ms.Enrol
	if pending {
		enrol = ms.EnrolPending
	}
	secret, uri, err := enrol(client, "openwrt-mcp", device)
	if err != nil {
		return err
	}

	if asJSON {
		png, err := qrcode.Encode(uri, qrcode.Medium, enrolPNGSize)
		if err != nil {
			return fmt.Errorf("encoding QR: %w", err)
		}
		return json.NewEncoder(out).Encode(struct {
			Client      string `json:"client"`
			URI         string `json:"uri"`
			Secret      string `json:"secret"`
			QRPNGBase64 string `json:"qr_png_base64"`
		}{client, uri, secret, base64.StdEncoding.EncodeToString(png)})
	}

	qrBlock := ""
	if qr {
		art, err := renderQR(uri)
		if err != nil {
			return err
		}
		qrBlock = indent(art, "  ") + "\n"
	}

	if pending {
		fmt.Fprintf(out, "Enrolment for %q is pending (not in force yet). Scan this in your authenticator app:\n\n  %s\n\n%s"+
			"  secret: %s\n\n"+
			"Then prove the scan worked, which activates it, with a current code:\n"+
			"  openwrt-mcp mfa activate %s <6-digit code>\n"+
			"Until then any secret already in force keeps working and this one unlocks nothing.\n",
			client, uri, qrBlock, secret, client)
		return nil
	}

	// Printed once, like a pairing token -- but unlike one this IS recoverable from
	// the state file, so say plainly that the file is credential material.
	fmt.Fprintf(out, "Enrolled %q. Scan this in your authenticator app:\n\n  %s\n\n%s"+
		"  secret: %s\n\n"+
		"Then require it for the tools that matter, e.g. in %s:\n"+
		"  list mfa_tools 'exec'\n"+
		"  list mfa_tools 'uci_apply'\n"+
		"  option mfa_window '15m'\n\n"+
		"Restart to apply: /etc/init.d/openwrt-mcp restart\n"+
		"The secret is stored at %s/mfa (mode 0600); anyone who reads it can generate codes.\n",
		client, uri, qrBlock, secret, defaultConfigPath, statePath)
	return nil
}

// runMFAActivate implements `mfa activate <client> <code>`.
func runMFAActivate(out io.Writer, ms *MFAStore, args []string, now time.Time) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: openwrt-mcp mfa activate <client> <6-digit code>")
	}
	if err := ms.Activate(args[0], args[1], now); err != nil {
		return err
	}
	fmt.Fprintf(out, "TOTP activated for %q. It takes effect on a running daemon without a restart.\n", args[0])
	return nil
}

// indent prefixes every non-empty line.
func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
