package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// An agent in an unlock window may change the router's settings, its VPN and its services. It
// may never make the router run a program of its choosing. Policies cannot say that: a grant is a
// glob over "config.section.option", and "firewall.*" covers a firewall rule and a firewall
// include alike, though an include's `path` is a script fw4 runs as root on every reload, and
// uci_apply triggers that reload itself. So uci_apply refuses, for every client, always, any
// change that would make the router execute a file or load configuration that can execute one.
// There is no switch: a switch the agent can reach is a switch the agent can flip.
//
// The decision is made before anything is staged, over the whole batch: one refused change and
// nothing in the batch is applied.
//
// What is refused, each entry naming where in OpenWrt's sources it comes from:
//
//   - every change in a config whose every option becomes raw configuration of a daemon that can
//     load code (uciExecConfigs);
//   - creating a section of a type that runs something, and any option change in an existing
//     one, whichever way the section is named: "@include[0]", "@include[-1]", a name, or the
//     cfgXXXXXX id uci gives an anonymous section (uciExecSectionTypes);
//   - setting an option, in any config, whose name says it is a hook (uciExecOptionNames,
//     uciExecSuffixes), or one that is a hook only in particular configs (uciExecConfigOptions);
//   - a shell variable that changes what every later command runs (uciExecEnvNames), because
//     several packages load every option of their config into a shell variable of that name;
//   - a line break anywhere in a change: init scripts write uci values into daemons' config
//     files one per line, so a second line in a value is a second directive (dnsmasq.init's
//     xappend echoes "--domain=<value>" into the conf file, and "lan\ndhcp-script=/x" is two).
//
// What it deliberately allows: deleting a hook option, and deleting a whole section of a refused
// type. Removing a hook runs nothing. Deleting one OPTION of an include is refused, because
// deleting `enabled` switches a disabled include back on.
//
// What this does NOT cover, named so nobody assumes it:
//   - the exec tool, which is a root shell by design and is gated only by policy;
//   - ubus_call, which reaches rpcd's file.exec and every service's own ubus methods;
//   - options that write a file somewhere (dnsmasq and odhcpd `leasefile`, openvpn `log`), and
//     options that pick a file to read data from (dnsmasq `addnhosts`, `serversfile`,
//     `dhcphostsfile`; hostapd `eap_user_file`): data, not code, though a file written into the
//     wrong place can become code at the next boot;
//   - raw daemon directives that cannot run a program: wireless `hostapd_options` and
//     `hostapd_bss_options` (hostapd has no directive that executes), firewall `extra*`;
//   - services that give a shell by design, such as ttyd or rtty with their defaults: enabling
//     one is a setting, and whoever logs in still authenticates;
//   - a package this list does not know. The suffix families catch the usual spellings of a
//     hook, but a package that runs an option named something else entirely is not caught.

// uciExecConfigs are configs in which every change is refused. Each says why.
var uciExecConfigs = map[string]string{
	"nginx": "nginx-util (packages net/nginx-util/files/nginx.config): each option of a server section is " +
		"written out as a raw nginx directive, value unescaped ('access_log off; # logd openwrt' is the " +
		"shipped example), and `list include` pulls in any file; nginx runs as root (uci.conf.template: user root)",
	"ucitrack": "luci-reload (luci modules/luci-base/root/sbin/luci-reload, up to 23.05): runs each " +
		"section's `exec` command line and /etc/init.d/<init> for the configs LuCI applies",
}

// uciExecSectionTypes are section types that run something. The key is "config.type", or
// "*.type" for a type that runs something in any config.
var uciExecSectionTypes = map[string]string{
	"*.include": "firewall include (firewall4 fw4.uc parse_include: type 'script' runs `path` on every reload, " +
		"type 'nftables' loads it as ruleset; firewall3 includes.c the same); pbr include " +
		"(packages net/pbr init.d/pbr: `. \"$path\"`)",
	"snmpd.exec":   "net-snmp (packages net/net-snmp/files/snmpd.init snmpd_exec_add): runs `prog` on an SNMP query",
	"snmpd.extend": "net-snmp (snmpd.init snmpd_extend_add): runs `prog` on an SNMP query",
	"snmpd.pass":   "net-snmp (snmpd.init snmpd_pass_add): hands an OID subtree to `prog`",
	"luci.command": "luci-app-commands (luci applications/luci-app-commands commands.js): a shell command " +
		"line LuCI runs on request, without login when `public` is set",
	"rpcd.login": "rpcd (openwrt package/system/rpcd/files/rpcd.config): a login whose ACL can include " +
		"file.exec, reachable over HTTP with a password the change itself sets",
	"luci_statistics.collectd_exec_input": "luci-app-statistics (stat-genconfig config_exec): collectd's exec " +
		"plugin runs `cmdline`",
	"luci_statistics.collectd_exec_notify": "luci-app-statistics (stat-genconfig config_exec): collectd's exec " +
		"plugin runs `cmdline` on a notification",
}

// uciExecOptionNames are option names that run or load something in whatever config they sit.
var uciExecOptionNames = map[string]string{
	"extraconftext": "dnsmasq (dnsmasq.init: written verbatim into the conf dir, so it can say dhcp-script=)",
	"leasetrigger":  "odhcpd (openwrt/odhcpd src/config.c ODHCPD_ATTR_LEASETRIGGER: run on every lease change)",
	"interpreter":   "uhttpd (openwrt uhttpd.init -i): maps a file suffix to an interpreter uhttpd runs",
	"cgi_prefix":    "uhttpd (uhttpd.init -x): files under this URL prefix are executed as CGI",
	"lua_prefix":    "uhttpd (uhttpd.init -l/-L): a prefix and the Lua handler uhttpd runs for it",
	"ucode_prefix":  "uhttpd (uhttpd.init -o/-O): a prefix and the ucode handler uhttpd runs for it",
	"no_ubusauth":   "uhttpd (uhttpd.init -a): turns off session checks on /ubus, so anyone can call file.exec",
	"pppd_options":  "ppp, sstp (openwrt ppp.sh, packages sstp.sh): raw pppd options, which include plugin and connect",
	"sstp_options":  "sstp (packages net/sstp-client sstp.sh): raw sstpc options, which pass on to pppd",
	"csd_wrapper":   "openconnect (packages net/openconnect openconnect.sh --csd-wrapper): a program openconnect runs",
	"misc_path":     "keepalived (packages net/keepalived keepalived.init MISC_CHECK): a program run as a health check",
	"cmdline":       "luci-app-statistics (stat-genconfig config_exec): the command collectd's exec plugin runs",
	"plugindir":     "luci-app-statistics (stat-genconfig PluginDir): where collectd loads its plugins, shared libraries, from",
	"plugin":        "openvpn (packages net/openvpn openvpn.options, openvpn.uc --plugin): loads a shared library",
	"providers":     "openvpn (openvpn.options --providers): OpenSSL 3 providers, loaded as shared libraries",
	"pkcs11_providers": "openvpn (openvpn.options --pkcs11-providers): PKCS#11 modules, loaded as shared " +
		"libraries",
	"engine":                "openvpn (openvpn.options --engine): an OpenSSL engine, loaded as a shared library",
	"iproute":               "openvpn (openvpn.options --iproute): the program openvpn runs in place of ip",
	"script_security":       "openvpn (openvpn.uc: at 2 or more it wires every up/down/verify hook to a user script)",
	"route_up":              "openvpn (openvpn.uc --route-up via user_route_up): a script run as root",
	"route_pre_down":        "openvpn (openvpn.uc --route-pre-down): a script run as root",
	"ipchange":              "openvpn (openvpn.uc --ipchange): a script run as root",
	"client_connect":        "openvpn (openvpn.uc --client-connect): a script run as root",
	"client_disconnect":     "openvpn (openvpn.uc --client-disconnect): a script run as root",
	"client_crresponse":     "openvpn (openvpn.uc --client-crresponse): a script run as root",
	"learn_address":         "openvpn (openvpn.uc --learn-address): a script run as root",
	"tls_verify":            "openvpn (openvpn.uc --tls-verify): a script run as root",
	"tls_crypt_v2_verify":   "openvpn (openvpn.uc --tls-crypt-v2-verify): a script run as root",
	"auth_user_pass_verify": "openvpn (openvpn.uc --auth-user-pass-verify): a script run as root",
	"updown":                "strongswan (packages net/strongswan swanctl.init: `updown = ` in swanctl.conf): a script charon runs",
	"prog":                  "net-snmp (snmpd.init exec, extend and pass sections): the program snmpd runs",
	"include": "nginx (nginx-util nginx.config `list include`), collectd (stat-genconfig Include): pulls another " +
		"file in as configuration",
	"credentials": "acme (packages net/acme-common acme.init load_credentials: `eval procd_append_param env " +
		"\"$1\"`, so the value is shell)",
}

// uciExecSuffixes catch the families. An option is refused if its name, lower-cased, ends with
// any of these. Each lists the options it is there for.
var uciExecSuffixes = []struct{ suffix, from string }{
	{"script", "dnsmasq dhcpscript (openwrt dnsmasq.init: USER_DHCPSCRIPT, run on every lease event); " +
		"ddns update_script, ip_script (ddns-scripts dynamic_dns_functions.sh: sourced or eval'd); " +
		"openconnect script, token_script (openconnect.sh); uhttpd json_script (uhttpd.init -H); watchcat " +
		"script (watchcat.sh); travelmate uplink script (travelmate-functions.sh); sqm script " +
		"(sqm-scripts start-sqm: sourced from /usr/lib/sqm/<script>); keepalived vrrp_script script"},
	{"cmd", "adblock adb_fetchcmd and the other adb_*cmd (adblock.sh), banip ban_*cmd (banip-functions.sh), " +
		"travelmate trm_fetchcmd: the program each one runs; nut notifycmd, shutdowncmd"},
	{"command", "ttyd command (ttyd.init: the program a web terminal runs), dropbear ForceCommand " +
		"(dropbear.init), luci-app-commands command"},
	{"exec", "ucitrack exec (luci-reload); a hook's usual name"},
	{"hook", "a hook's usual name"},
	{"handler", "uhttpd lua_handler (uhttpd.init -L): the Lua script uhttpd runs"},
	{"parm", "adblock adb_fetchparm, adb_etagparm, adb_geoparm, banip ban_fetchparm, ban_rdapparm, " +
		"travelmate trm_fetchparm: arguments word-split onto the fetch command line, where curl's -o or -K " +
		"writes or reads any file"},
	{"conffile", "dnsmasq --conf-file and the like: a whole config file loaded"},
	{"conf_file", "the same, spelled with an underscore"},
	{"confdir", "dnsmasq confdir (dnsmasq.init --conf-dir): every file in it is loaded, dhcp-script= included"},
	{"conf_dir", "the same, spelled with an underscore"},
	{"config_file", "nebula config_file (packages net/nebula nebula.proto: eval'd through yaml_parse, then " +
		"loaded by nebula)"},
}

// uciExecExempt are names a suffix catches that run nothing. The list is kept as short as it can
// be: an entry here is the one way a name ending in "script" gets through.
var uciExecExempt = map[string]string{
	"track_script": "keepalived (keepalived.init): names of vrrp_script sections, whose own `script` is refused",
	"ifconfig_noexec": "openvpn (openvpn.options, a boolean): stops openvpn running ifconfig, so it only " +
		"ever removes an exec",
	"route_noexec": "openvpn (openvpn.options, a boolean): stops openvpn running route, so it only ever " +
		"removes an exec",
}

// uciExecConfigOptions are hooks only in the config named: elsewhere the same word means
// something harmless (mwan3's `up` and `down` are ping counts). The key is "config.option".
var uciExecConfigOptions = map[string]string{
	"network.up": "openvpn as a netifd protocol (packages net/openvpn openvpn.uc --up via user_up): a " +
		"script run as root",
	"network.down":       "openvpn as a netifd protocol (openvpn.uc --down via user_down): a script run as root",
	"network.config":     "openvpn as a netifd protocol (openvpn.uc --config): a whole openvpn config, which can name scripts",
	"network.connect":    "ppp (openwrt ppp.sh 'connect:file'): a program pppd runs to dial",
	"network.disconnect": "ppp (ppp.sh 'disconnect:file'): a program pppd runs to hang up",
	"openvpn.up":         "openvpn before 25.12 (/etc/config/openvpn, openvpn.options OPENVPN_PARAMS_FILE): a script",
	"openvpn.down":       "openvpn before 25.12 (openvpn.options OPENVPN_PARAMS_FILE): a script",
	"openvpn.config":     "openvpn before 25.12 (openvpn.options OPENVPN_PARAMS_FILE): a whole openvpn config",
	"uhttpd.home": "uhttpd (uhttpd.init -h): the document root, under which cgi_prefix decides what is " +
		"executed as CGI",
	"acme.dns": "acme (acme.init --dns; acme.sh _findHook): the dnsapi hook acme.sh sources, looked up as " +
		"$_SCRIPT_HOME/dnsapi/<name>, so a name with a / in it reaches any file",
	"sqm.script": "sqm-scripts (start-sqm: `. \"${SQM_LIB_DIR}/$SCRIPT\"`), so a name with a / in it " +
		"sources any file",
}

// uciExecPlainNameOK are the config options above whose value only picks an installed script out
// of a fixed directory. A plain file name (letters, digits, '_', '-', '.', and not "..") is
// allowed: it can only name what is already installed there.
var uciExecPlainNameOK = map[string]string{
	"acme.dns":   "a dnsapi hook name, such as dns_cf",
	"sqm.script": "a queueing script, such as piece_of_cake.qos",
}

// uciExecEnvNames are shell variables that change what every later command in a script runs.
// adblock.sh, banip-functions.sh and travelmate-functions.sh load every option of their config
// into a shell variable of the option's name (their option_cb: eval "${option}=..."), so an
// option called PATH is the PATH their scripts run with. Compared exactly: an option called
// "path" (a firewall include's, a radio's) is a different name to the shell.
var uciExecEnvNames = map[string]string{
	"PATH":            "the directories every command name is looked up in",
	"LD_PRELOAD":      "shared libraries loaded into every program started",
	"LD_LIBRARY_PATH": "the directories shared libraries are loaded from",
}

var plainName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// typeSelector matches uci's "@type[index]" selector, whose type is the section's type by
// definition.
var typeSelector = regexp.MustCompile(`^@([^\[\]]+)\[-?[0-9]+\]$`)

// execOptionReason says why setting this option to this value would make the router run code,
// or returns "".
func execOptionReason(config, option, value string) string {
	if why, ok := uciExecEnvNames[strings.TrimSpace(option)]; ok {
		return "a shell variable some packages load every option into: " + why
	}
	n := strings.ToLower(strings.TrimSpace(option))
	if n == "" {
		return ""
	}
	if why, ok := uciExecConfigOptions[config+"."+n]; ok {
		if _, plain := uciExecPlainNameOK[config+"."+n]; plain && plainName.MatchString(value) &&
			!strings.Contains(value, "..") {
			return ""
		}
		return why
	}
	if _, ok := uciExecExempt[n]; ok {
		return ""
	}
	if why, ok := uciExecOptionNames[n]; ok {
		return why
	}
	for _, s := range uciExecSuffixes {
		if strings.HasSuffix(n, s.suffix) {
			return s.from
		}
	}
	return ""
}

// execSectionTypeReason says why a section of this type in this config runs code, or "".
func execSectionTypeReason(config, typ string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	if why, ok := uciExecSectionTypes[config+"."+t]; ok {
		return why
	}
	if why, ok := uciExecSectionTypes["*."+t]; ok {
		return why
	}
	return ""
}

// selectorType is the type a "@type[n]" selector names, or "".
func selectorType(section string) string {
	if m := typeSelector.FindStringSubmatch(section); m != nil {
		return m[1]
	}
	return ""
}

// execRefusal says why this change would make the router run code, or returns "". types are the
// types the change's section has now on the router (more than one only if uci's output was odd:
// every type seen counts).
func execRefusal(c UCIChange, types []string) string {
	if why, ok := uciExecConfigs[c.Config]; ok {
		return why
	}
	for _, f := range []string{c.Config, c.Section, c.Option, c.Type, c.Value} {
		if strings.ContainsAny(f, "\n\r") {
			return "a line break: init scripts write uci values into config files one per line, so a " +
				"second line in a value is a second directive (dnsmasq.init xappend)"
		}
	}
	if c.Type != "" {
		return execSectionTypeReason(c.Config, c.Type)
	}
	if c.Option == "" {
		return "" // deleting a whole section, whatever its type, runs nothing
	}
	if t := selectorType(c.Section); t != "" {
		types = append([]string{t}, types...)
	}
	for _, t := range types {
		if why := execSectionTypeReason(c.Config, t); why != "" {
			return "an option of a section of type " + t + ", " + why
		}
	}
	if c.Delete {
		return "" // removing a hook runs nothing
	}
	return execOptionReason(c.Config, c.Option, c.Value)
}

// parseUCISectionTypes reads `uci -X show <config>` and returns the type of every section, keyed
// by the name uci printed (a cfgXXXXXX id for an anonymous one, because of -X). A section line is
// "config.section=type"; a line whose section part holds a dot is an option. Every type seen for
// a name is kept: a value spread over lines can imitate a section line, and keeping all of them
// means an imitation can only add a type to check, never hide the real one.
func parseUCISectionTypes(config, out string) map[string][]string {
	types := map[string][]string{}
	prefix := config + "."
	for _, line := range strings.Split(out, "\n") {
		eq := strings.IndexByte(line, '=')
		if eq < 0 || !strings.HasPrefix(line, prefix) {
			continue
		}
		section := line[len(prefix):eq]
		if section == "" || strings.Contains(section, ".") {
			continue
		}
		typ := strings.Trim(line[eq+1:], "'")
		types[section] = append(types[section], typ)
	}
	return types
}

// refusedError is a refusal by rule, as opposed to a failure: the tool wrapper audits it as
// DENIED.
type refusedError struct{ msg string }

func (e *refusedError) Error() string { return e.msg }

func isRefused(err error) bool {
	var r *refusedError
	return errors.As(err, &r)
}

// refuseCodeExec checks the whole batch and returns a refusedError naming every change that
// would make the router run code, or nil. It reads `uci -X show` once for each config with an
// option-level change; if that read fails, the answer is no, because a section whose type
// cannot be read could be an include.
func refuseCodeExec(ctx context.Context, changes []UCIChange) error {
	shown := map[string]map[string][]string{}
	var lines []string
	for _, c := range changes {
		var types []string
		if _, whole := uciExecConfigs[c.Config]; !whole && c.Type == "" && c.Option != "" &&
			selectorType(c.Section) == "" {
			st, ok := shown[c.Config]
			if !ok {
				out, err := run(ctx, defaultCmdTimeout, "uci", "-X", "show", c.Config)
				if err != nil {
					return &refusedError{fmt.Sprintf("refused: cannot tell what kind of section %s is "+
						"(uci -X show %s failed: %v), and an include runs code as root; nothing was applied",
						c.Config+"."+c.Section, c.Config, err)}
				}
				st = parseUCISectionTypes(c.Config, out)
				shown[c.Config] = st
			}
			types = st[c.Section]
		}
		if why := execRefusal(c, types); why != "" {
			lines = append(lines, fmt.Sprintf("refused: %s makes the router run code as root; "+
				"openwrt-mcp never applies that (%s)", uciKey(c), why))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return &refusedError{strings.Join(lines, "\n") + "\nNothing in this batch was applied. " +
		"Ask the operator to make that change by hand if it is wanted."}
}
