// nmapresponder parses nmap normal (.nmap) output (from stdin or a file),
// looks up public exploits/CVEs via searchsploit, maps them to the open
// ports, and suggests enumeration tools & commands per service.
//
// Feed it the plain-text output nmap writes with -oN (the ".nmap" file),
// not the XML (-oX) output.
//
// Usage:
//
//	nmap -sV -oN - <target> | nmapresponder
//	nmap -sV -oN scan.nmap <target> && nmapresponder -f scan.nmap
//
// Flags:
//
//	-f <file>     read nmap .nmap output from a file instead of stdin
//	-t <target>   target host/IP used in the suggested commands (default: the
//	              scanned address from the output, or TARGET placeholder)
//	-no-exploits  skip the searchsploit lookups (just enumeration suggestions)
//	-no-color     disable ANSI colors
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// parsed nmap structures (only the fields we care about)
// ---------------------------------------------------------------------------

type nmapRun struct {
	Hosts []host
}

type host struct {
	Addresses []address
	Hostnames []hostname
	Ports     []port
	Scripts   []string // "Host script results:" lines
	OSInfo    string   // "Service Info:" line
}

type hostname struct {
	Name string
}

type address struct {
	Addr     string
	AddrType string
}

type port struct {
	Protocol string
	PortID   string
	State    state
	Service  service
	Scripts  []string // NSE script output lines attached to this port
}

type state struct {
	State string
}

type service struct {
	Name      string
	Product   string
	Version   string
	ExtraInfo string
	Tunnel    string
	Banner    string // raw VERSION column text, as printed by nmap
}

// ---------------------------------------------------------------------------
// searchsploit JSON structures (searchsploit -j)
// ---------------------------------------------------------------------------

type searchsploitResult struct {
	ResultsExploit []exploitEntry `json:"RESULTS_EXPLOIT"`
}

type exploitEntry struct {
	Title   string `json:"Title"`
	EdbID   string `json:"EDB-ID"`
	Date    string `json:"Date_Published"`
	Type    string `json:"Type"`
	Platform string `json:"Platform"`
	Path    string `json:"Path"`
	Codes   string `json:"Codes"` // CVE / OSVDB references, ';'-separated
}

// ---------------------------------------------------------------------------
// colors
// ---------------------------------------------------------------------------

var (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
)

func disableColor() {
	cReset, cBold, cRed, cGreen, cYellow, cBlue, cCyan, cGray = "", "", "", "", "", "", "", ""
}

// ---------------------------------------------------------------------------
// enumeration playbook: service name / port -> tools & commands
// {{T}} is replaced with the target, {{P}} with the port.
// ---------------------------------------------------------------------------

type play struct {
	note     string
	commands []string
}

// keyed by nmap service name (lowercased)
var serviceBook = map[string]play{
	"ftp": {
		note: "Try anonymous login; check for writable dirs and known daemon CVEs.",
		commands: []string{
			"ftp {{T}} {{P}}   # try user 'anonymous', pass 'anonymous'",
			"nmap -p {{P}} --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor {{T}}",
			"hydra -L users.txt -P pass.txt ftp://{{T}}:{{P}}",
		},
	},
	"ssh": {
		note: "Enumerate auth methods & host key; brute only with permission.",
		commands: []string{
			"ssh-audit {{T}}:{{P}}",
			"nmap -p {{P}} --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods {{T}}",
			"hydra -L users.txt -P pass.txt ssh://{{T}}:{{P}}",
		},
	},
	"telnet": {
		note: "Grab banner; try default/weak creds.",
		commands: []string{
			"telnet {{T}} {{P}}",
			"nmap -p {{P}} --script telnet-ntlm-info,telnet-encryption {{T}}",
		},
	},
	"smtp": {
		note: "Enumerate users (VRFY/EXPN/RCPT) and open-relay.",
		commands: []string{
			"nmap -p {{P}} --script smtp-commands,smtp-enum-users,smtp-open-relay {{T}}",
			"smtp-user-enum -M VRFY -U users.txt -t {{T}}",
		},
	},
	"domain": {
		note: "DNS: try zone transfer and record enumeration.",
		commands: []string{
			"dig axfr @{{T}} <domain>",
			"nmap -p {{P}} --script dns-nsid,dns-recursion {{T}}",
			"dnsrecon -n {{T}} -d <domain>",
		},
	},
	"http": {
		note: "Web app recon: headers, dirs, vhosts, tech fingerprinting.",
		commands: []string{
			"whatweb http://{{T}}:{{P}}",
			"nikto -h http://{{T}}:{{P}}",
			"feroxbuster -u http://{{T}}:{{P}} -w /usr/share/seclists/Discovery/Web-Content/common.txt",
			"ffuf -u http://{{T}}:{{P}}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
			"nmap -p {{P}} --script http-enum,http-title,http-headers,http-methods {{T}}",
		},
	},
	"https": {
		note: "As HTTP, plus TLS inspection.",
		commands: []string{
			"whatweb https://{{T}}:{{P}}",
			"nikto -h https://{{T}}:{{P}}",
			"sslscan {{T}}:{{P}}",
			"feroxbuster -u https://{{T}}:{{P}} -w /usr/share/seclists/Discovery/Web-Content/common.txt -k",
			"nmap -p {{P}} --script ssl-cert,ssl-enum-ciphers,http-enum {{T}}",
		},
	},
	"microsoft-ds": {
		note: "SMB: shares, null sessions, OS info, known CVEs (EternalBlue etc.).",
		commands: []string{
			"smbclient -L //{{T}}/ -N",
			"enum4linux-ng -A {{T}}",
			"nmap -p {{P}} --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-* {{T}}",
			"crackmapexec smb {{T}}",
		},
	},
	"netbios-ssn": {
		note: "SMB/NetBIOS: shares and null sessions.",
		commands: []string{
			"smbclient -L //{{T}}/ -N",
			"enum4linux-ng -A {{T}}",
			"nmap -p {{P}} --script smb-enum-shares,smb-enum-users,smb-vuln-* {{T}}",
		},
	},
	"ms-sql-s": {
		note: "MSSQL: version, logins, xp_cmdshell.",
		commands: []string{
			"nmap -p {{P}} --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password {{T}}",
			"impacket-mssqlclient <user>:<pass>@{{T}}",
		},
	},
	"mysql": {
		note: "MySQL: version, users, empty passwords.",
		commands: []string{
			"nmap -p {{P}} --script mysql-info,mysql-empty-password,mysql-users {{T}}",
			"mysql -h {{T}} -P {{P}} -u root -p",
		},
	},
	"postgresql": {
		note: "Postgres: default creds, databases.",
		commands: []string{
			"nmap -p {{P}} --script pgsql-brute {{T}}",
			"psql -h {{T}} -p {{P}} -U postgres",
		},
	},
	"ms-wbt-server": {
		note: "RDP: NLA status, known CVEs (BlueKeep), weak creds.",
		commands: []string{
			"nmap -p {{P}} --script rdp-ntlm-info,rdp-enum-encryption {{T}}",
			"xfreerdp /v:{{T}}:{{P}} /u:<user> /p:<pass>",
			"crackmapexec rdp {{T}}",
		},
	},
	"rpcbind": {
		note: "RPC: enumerate exported services / NFS.",
		commands: []string{
			"rpcinfo -p {{T}}",
			"nmap -p {{P}} --script rpcinfo,nfs-ls,nfs-showmount {{T}}",
			"showmount -e {{T}}",
		},
	},
	"ldap": {
		note: "LDAP: anonymous bind and naming contexts.",
		commands: []string{
			"ldapsearch -x -H ldap://{{T}}:{{P}} -s base namingcontexts",
			"nmap -p {{P}} --script ldap-rootdse,ldap-search {{T}}",
		},
	},
	"snmp": {
		note: "SNMP: community strings and full MIB walk.",
		commands: []string{
			"onesixtyone {{T}} public",
			"snmpwalk -v2c -c public {{T}}",
			"nmap -sU -p {{P}} --script snmp-info,snmp-interfaces,snmp-processes {{T}}",
		},
	},
	"vnc": {
		note: "VNC: auth type and weak/no password.",
		commands: []string{
			"nmap -p {{P}} --script vnc-info,realvnc-auth-bypass {{T}}",
			"vncviewer {{T}}:{{P}}",
		},
	},
	"redis": {
		note: "Redis: unauthenticated access, info, keys.",
		commands: []string{
			"redis-cli -h {{T}} -p {{P}} info",
			"nmap -p {{P}} --script redis-info {{T}}",
		},
	},
	"mongodb": {
		note: "MongoDB: unauthenticated access, databases.",
		commands: []string{
			"mongo {{T}}:{{P}} --eval 'db.adminCommand({listDatabases:1})'",
			"nmap -p {{P}} --script mongodb-info,mongodb-databases {{T}}",
		},
	},
}

// fallback keyed by port number for services nmap couldn't name well
var portBook = map[string]play{
	"8080": serviceBook["http"],
	"8000": serviceBook["http"],
	"8443": serviceBook["https"],
	"445":  serviceBook["microsoft-ds"],
	"139":  serviceBook["netbios-ssn"],
	"3389": serviceBook["ms-wbt-server"],
}

// ---------------------------------------------------------------------------
// parser for nmap's normal (-oN / .nmap) text output
// ---------------------------------------------------------------------------

// parseNmapText walks the plain-text nmap report, collecting hosts and the
// rows of their PORT/STATE/SERVICE/VERSION tables.
const (
	modeNone = iota
	modePorts
	modeHostScripts
)

func parseNmapText(data []byte) nmapRun {
	var run nmapRun
	var cur *host
	var curPort *port
	mode := modeNone

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if rest, ok := strings.CutPrefix(line, "Nmap scan report for "); ok {
			name, addr := parseHostTarget(rest)
			h := host{}
			if addr != "" {
				h.Addresses = append(h.Addresses, address{Addr: addr, AddrType: "ipv4"})
			}
			if name != "" {
				h.Hostnames = append(h.Hostnames, hostname{Name: name})
			}
			run.Hosts = append(run.Hosts, h)
			cur = &run.Hosts[len(run.Hosts)-1]
			curPort = nil
			mode = modeNone
			continue
		}

		if cur == nil {
			continue
		}

		// NSE script output ("| ..." / "|_...") belongs to the most recent
		// port, or to the host when under "Host script results:".
		if strings.HasPrefix(line, "|") {
			text := cleanScriptLine(line)
			if text == "" {
				continue
			}
			if mode == modePorts && curPort != nil {
				curPort.Scripts = append(curPort.Scripts, text)
			} else {
				cur.Scripts = append(cur.Scripts, text)
			}
			continue
		}

		// The port table starts at the "PORT  STATE  SERVICE ..." header.
		if strings.HasPrefix(line, "PORT") && strings.Contains(line, "STATE") {
			mode = modePorts
			curPort = nil
			continue
		}
		if strings.HasPrefix(line, "Host script results:") {
			mode = modeHostScripts
			curPort = nil
			continue
		}
		if rest, ok := strings.CutPrefix(line, "Service Info:"); ok {
			cur.OSInfo = strings.TrimSpace(rest)
			continue
		}

		if mode == modePorts {
			if p, ok := parsePortLine(line); ok {
				cur.Ports = append(cur.Ports, p)
				curPort = &cur.Ports[len(cur.Ports)-1]
				continue
			}
			// a non-port, non-script line ends the port table
			mode = modeNone
			curPort = nil
		}
	}
	return run
}

// cleanScriptLine strips the leading "|_" / "|" gutter nmap draws on script
// output lines.
func cleanScriptLine(line string) string {
	line = strings.TrimPrefix(line, "|_")
	line = strings.TrimPrefix(line, "|")
	return strings.TrimSpace(line)
}

// parseHostTarget splits "example.com (1.2.3.4)" or a bare host/IP.
func parseHostTarget(s string) (name, addr string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "("); i >= 0 {
		name = strings.TrimSpace(s[:i])
		rest := s[i+1:]
		if j := strings.Index(rest, ")"); j >= 0 {
			addr = strings.TrimSpace(rest[:j])
		}
		return name, addr
	}
	// bare token: use it as the address so it still drives the commands
	return "", s
}

// parsePortLine parses a row like:
//
//	22/tcp   open  ssh      OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; ...)
//	443/tcp  open  ssl/http Apache httpd 2.4.49
func parsePortLine(line string) (port, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return port{}, false
	}
	portID, proto, ok := strings.Cut(fields[0], "/")
	if !ok || !isAllDigits(portID) {
		return port{}, false
	}

	st := fields[1]
	svc := service{}
	if len(fields) >= 3 {
		// nmap appends '?' to uncertain service guesses (e.g. "rpcbind?").
		svc.Name = strings.TrimSuffix(fields[2], "?")
	}
	if len(fields) >= 4 {
		svc.Banner = strings.Join(fields[3:], " ")
	}
	if rest, ok := strings.CutPrefix(svc.Name, "ssl/"); ok {
		svc.Tunnel = "ssl"
		svc.Name = rest
	}
	svc.Product, svc.Version = splitProductVersion(svc.Banner)

	return port{
		Protocol: proto,
		PortID:   portID,
		State:    state{State: st},
		Service:  svc,
	}, true
}

// splitProductVersion makes a best-effort guess of product and version from
// nmap's free-form VERSION column, for the searchsploit query.
func splitProductVersion(banner string) (product, version string) {
	var prod []string
	for _, f := range strings.Fields(banner) {
		if f[0] == '(' { // start of parenthetical extrainfo
			break
		}
		if f[0] >= '0' && f[0] <= '9' { // first version-looking token
			version = f
			break
		}
		prod = append(prod, f)
	}
	return strings.Join(prod, " "), version
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------

func main() {
	var (
		file        string
		target      string
		noExploits  bool
		noColor     bool
	)
	flag.StringVar(&file, "f", "", "read nmap XML from this file instead of stdin")
	flag.StringVar(&target, "t", "", "target used in suggested commands (defaults to scanned address)")
	flag.BoolVar(&noExploits, "no-exploits", false, "skip searchsploit lookups")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	flag.Parse()

	if noColor || os.Getenv("NO_COLOR") != "" {
		disableColor()
	}

	var reader io.Reader = os.Stdin
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fatal("cannot open %s: %v", file, err)
		}
		defer f.Close()
		reader = f
	} else {
		// If stdin is a terminal (no pipe), warn the user.
		if fi, _ := os.Stdin.Stat(); fi.Mode()&os.ModeCharDevice != 0 {
			fatal("no input on stdin. Pipe nmap .nmap output, e.g.:\n  nmap -sV -oN - <target> | %s\nor use -f scan.nmap", os.Args[0])
		}
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		fatal("read input: %v", err)
	}

	run := parseNmapText(data)
	if len(run.Hosts) == 0 {
		fatal("no nmap hosts found in the input\n(feed the normal -oN output, i.e. the .nmap file, not the -oX XML)")
	}

	ssAvailable := true
	if !noExploits {
		if _, err := exec.LookPath("searchsploit"); err != nil {
			ssAvailable = false
			warn("searchsploit not found in PATH; skipping exploit lookups. Install exploitdb to enable them.")
		}
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	printBanner(out)

	totalOpen := 0
	for _, h := range run.Hosts {
		hostTarget := target
		if hostTarget == "" {
			hostTarget = primaryAddr(h)
		}
		if hostTarget == "" {
			hostTarget = "TARGET"
		}

		fmt.Fprintf(out, "\n%s%s══ Host: %s ══%s\n", cBold, cCyan, hostDisplay(h, hostTarget), cReset)

		for _, p := range h.Ports {
			if !strings.HasPrefix(p.State.State, "open") {
				continue
			}
			totalOpen++
			printPort(out, p, hostTarget, ssAvailable && !noExploits)
		}

		if h.OSInfo != "" {
			fmt.Fprintf(out, "\n  %s↳ service info:%s %s\n", cBlue, cReset, h.OSInfo)
		}
		if s := usefulScripts(h.Scripts); len(s) > 0 {
			fmt.Fprintf(out, "\n  %s↳ host scripts:%s\n", cCyan, cReset)
			for _, l := range s {
				fmt.Fprintf(out, "      %s%s%s\n", cGray, l, cReset)
			}
		}
	}

	if totalOpen == 0 {
		fmt.Fprintf(out, "\n%sNo open ports found in the nmap output.%s\n", cYellow, cReset)
	}
	fmt.Fprintf(out, "\n%sDone. %d open port(s) analyzed.%s\n", cGray, totalOpen, cReset)
}

func printPort(out *bufio.Writer, p port, target string, doExploits bool) {
	svc := p.Service
	name := svc.Name
	if svc.Tunnel == "ssl" && name == "http" {
		name = "https"
	}

	banner := strings.TrimSpace(svc.Banner)
	if banner == "" {
		banner = strings.TrimSpace(strings.Join(nonEmpty(svc.Product, svc.Version, svc.ExtraInfo), " "))
	}
	if banner == "" {
		banner = name
	}

	fmt.Fprintf(out, "\n%s%s[%s/%s]%s %s%s%s  %s%s%s\n",
		cBold, cGreen, p.PortID, p.Protocol, cReset,
		cBold, name, cReset,
		cGray, banner, cReset)

	// enumeration suggestions
	pl, ok := serviceBook[strings.ToLower(name)]
	if !ok {
		pl, ok = portBook[p.PortID]
	}
	if ok {
		fmt.Fprintf(out, "  %s↳ enum:%s %s\n", cBlue, cReset, pl.note)
		for _, c := range pl.commands {
			fmt.Fprintf(out, "      %s%s%s\n", cGray, expand(c, target, p.PortID), cReset)
		}
	} else {
		fmt.Fprintf(out, "  %s↳ enum:%s no built-in playbook for '%s'; grab the banner and research the product/version.\n", cBlue, cReset, name)
		fmt.Fprintf(out, "      %snc -nv %s %s   # manual banner grab%s\n", cGray, target, p.PortID, cReset)
	}

	// nmap script (NSE) output captured for this port
	if s := usefulScripts(p.Scripts); len(s) > 0 {
		fmt.Fprintf(out, "  %s↳ nmap scripts:%s\n", cCyan, cReset)
		for _, l := range s {
			fmt.Fprintf(out, "      %s%s%s\n", cGray, l, cReset)
		}
	}

	// exploit lookup
	if doExploits {
		term := searchTerm(svc)
		if term == "" {
			fmt.Fprintf(out, "  %s↳ exploits:%s no product/version in banner to search.\n", cYellow, cReset)
			return
		}
		entries, err := runSearchsploit(term)
		if err != nil {
			fmt.Fprintf(out, "  %s↳ exploits:%s searchsploit error for '%s': %v\n", cYellow, cReset, term, err)
			return
		}
		if len(entries) == 0 {
			fmt.Fprintf(out, "  %s↳ exploits:%s none found for '%s'.\n", cYellow, cReset, term)
			return
		}
		fmt.Fprintf(out, "  %s↳ exploits%s (searchsploit '%s'):\n", cRed, cReset, term)
		for _, e := range topN(entries, 12) {
			cves := extractCVEs(e.Codes)
			cveStr := ""
			if len(cves) > 0 {
				cveStr = "  " + cYellow + strings.Join(cves, ", ") + cReset
			}
			fmt.Fprintf(out, "      %s[EDB-%s]%s %s%s\n", cRed, e.EdbID, cReset, e.Title, cveStr)
		}
		fmt.Fprintf(out, "      %sinspect/copy: searchsploit -p <EDB-ID>%s\n", cGray, cReset)
	}
}

// searchTerm builds a searchsploit query from the service banner.
// usefulScripts drops the "Script execution failed" noise nmap emits for
// scripts that errored out, keeping the lines that actually say something.
func usefulScripts(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, "ERROR: Script execution failed") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func searchTerm(s service) string {
	product := strings.TrimSpace(s.Product)
	if product == "" {
		return ""
	}
	// Keep product + major version; searchsploit matches all words (AND),
	// so too much detail returns nothing.
	version := strings.TrimSpace(s.Version)
	if version != "" {
		// take just the first token of the version, e.g. "2.4.49" -> "2.4.49"
		// but drop trailing noise like "(Ubuntu)"
		version = strings.Fields(version)[0]
		return product + " " + version
	}
	return product
}

func runSearchsploit(term string) ([]exploitEntry, error) {
	// -j JSON, --colour disables ANSI inside JSON
	cmd := exec.Command("searchsploit", "-j", term)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		// searchsploit exits non-zero on "no results" in some versions;
		// try to parse anyway before erroring.
		var r searchsploitResult
		if jerr := json.Unmarshal([]byte(outBuf.String()), &r); jerr == nil {
			return r.ResultsExploit, nil
		}
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", msg)
	}
	var r searchsploitResult
	if err := json.Unmarshal([]byte(outBuf.String()), &r); err != nil {
		return nil, fmt.Errorf("decode json: %v", err)
	}
	return r.ResultsExploit, nil
}

// extractCVEs pulls CVE-IDs out of searchsploit's Codes field.
func extractCVEs(codes string) []string {
	if codes == "" {
		return nil
	}
	var out []string
	for _, part := range strings.FieldsFunc(codes, func(r rune) bool {
		return r == ';' || r == ' ' || r == ','
	}) {
		if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
			out = append(out, strings.ToUpper(part))
		}
	}
	sort.Strings(out)
	return out
}

func topN(e []exploitEntry, n int) []exploitEntry {
	if len(e) > n {
		return e[:n]
	}
	return e
}

func expand(s, target, portID string) string {
	s = strings.ReplaceAll(s, "{{T}}", target)
	s = strings.ReplaceAll(s, "{{P}}", portID)
	return s
}

func primaryAddr(h host) string {
	// prefer IPv4, then IPv6, then any
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	for _, a := range h.Addresses {
		if a.Addr != "" {
			return a.Addr
		}
	}
	return ""
}

func hostDisplay(h host, target string) string {
	if len(h.Hostnames) > 0 && h.Hostnames[0].Name != "" {
		return fmt.Sprintf("%s (%s)", target, h.Hostnames[0].Name)
	}
	return target
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func printBanner(out *bufio.Writer) {
	fmt.Fprintf(out, "%s%sNmapResponder%s %s— ports → exploits (searchsploit) + enum playbook%s\n",
		cBold, cCyan, cReset, cGray, cReset)
}

func warn(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "%swarning:%s "+format+"\n", append([]interface{}{cYellow, cReset}, a...)...)
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "%serror:%s "+format+"\n", append([]interface{}{cRed, cReset}, a...)...)
	os.Exit(1)
}
