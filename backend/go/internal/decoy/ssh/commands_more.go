package ssh

// More of an Ubuntu 22.04 userland, plus the shell features attackers type most: variables, command substitution,
// for / while-read loops. Everything is emulated over the fake filesystem; nothing is ever executed or sent out.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxLoopIterations = 50 // for / while read: bound the work one line can cause
	maxSubstDepth     = 3  // nested $( ) / backticks
)

func registerMore(m map[string]cmdFunc) {
	// text tools (real behaviour on fake data)
	m["sed"] = cmdSed
	m["awk"] = cmdAwk
	m["gawk"] = cmdAwk
	m["mawk"] = cmdAwk
	m["sort"] = cmdSort
	m["uniq"] = cmdUniq
	m["cut"] = cmdCut
	m["tr"] = cmdTr
	m["tee"] = cmdTee
	m["xargs"] = cmdXargs
	m["base64"] = cmdBase64
	m["md5sum"] = hashCmd("md5")
	m["sha1sum"] = hashCmd("sha1")
	m["sha256sum"] = hashCmd("sha256")
	m["rev"] = cmdRev
	m["nl"] = cmdNl
	m["seq"] = cmdSeq
	m["less"] = cmdCat
	m["more"] = cmdCat
	m["zcat"] = cmdCat
	m["basename"] = func(_ *Shell, a []string, _ string, _ *Result) (string, int) {
		if len(a) == 0 {
			return "basename: missing operand\n", 1
		}
		return path.Base(a[0]) + "\n", 0
	}
	m["dirname"] = func(_ *Shell, a []string, _ string, _ *Result) (string, int) {
		if len(a) == 0 {
			return "dirname: missing operand\n", 1
		}
		return path.Dir(a[0]) + "\n", 0
	}
	m["realpath"] = cmdRealpath
	m["readlink"] = cmdRealpath
	m["stat"] = cmdStat
	m["file"] = cmdFile
	m["du"] = cmdDu
	m["test"] = cmdTest
	m["["] = cmdTest

	// system views (non-root answers, as on a stock Ubuntu 22.04 server)
	m["dmesg"] = msg("dmesg: read kernel buffer failed: Operation not permitted\n", 1)
	m["journalctl"] = msg("Hint: You are currently not seeing messages from other users and the system.\n"+
		"      Users in groups 'adm', 'systemd-journal' can see all messages.\n"+
		"      Pass -q to turn off this notice.\n-- No entries --\n", 0)
	m["strace"] = msg("strace: attach: ptrace(PTRACE_SEIZE, 1): Operation not permitted\n", 1)
	m["ltrace"] = msg("Command 'ltrace' not found, but can be installed with:\n\nsudo apt install ltrace\n", 127)
	m["lsof"] = cmdLsof
	m["systemctl"] = cmdSystemctl
	m["service"] = cmdService
	m["lsblk"] = cmdLsblk
	m["lscpu"] = cmdLscpu
	m["nproc"] = msg("4\n", 0)
	m["arch"] = msg("x86_64\n", 0)
	m["mount"] = cmdMount
	m["groups"] = func(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
		if sh.User.UID == 0 {
			return "root\n", 0
		}
		return sh.User.Name + " sudo docker\n", 0
	}
	m["getent"] = cmdGetent
	m["last"] = cmdLast
	m["lastlog"] = cmdLastlog
	m["users"] = func(sh *Shell, _ []string, _ string, _ *Result) (string, int) { return sh.User.Name + "\n", 0 }
	m["who"] = func(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
		return fmt.Sprintf("%-8s pts/0        %s (10.0.0.1)\n", sh.User.Name, sh.Started.Format("2006-01-02 15:04")), 0
	}
	m["tty"] = msg("/dev/pts/0\n", 0)
	m["locale"] = msg("LANG=en_US.UTF-8\nLANGUAGE=\nLC_CTYPE=\"en_US.UTF-8\"\nLC_ALL=\n", 0)
	m["umask"] = msg("0002\n", 0)
	m["ulimit"] = msg("unlimited\n", 0)
	m["type"] = cmdType
	m["command"] = cmdType
	m["whereis"] = func(_ *Shell, a []string, _ string, _ *Result) (string, int) {
		var b strings.Builder
		for _, x := range a {
			if _, ok := commands[x]; ok {
				fmt.Fprintf(&b, "%s: /usr/bin/%s /usr/share/man/man1/%s.1.gz\n", x, x, x)
			} else {
				fmt.Fprintf(&b, "%s:\n", x)
			}
		}
		return b.String(), 0
	}
	m["man"] = msg("This system has been minimized by removing packages and content that are\n"+
		"not required on a system that users do not log into.\n\nTo restore this content, including manpages, you can run the 'unminimize'\n"+
		"command. You will still need to ensure the 'man-db' package is installed.\n", 0)

	// package management, editors, privileged or interactive tools: what a non-root user really sees
	m["apt"] = cmdApt
	m["apt-get"] = cmdApt
	m["dpkg"] = cmdDpkg
	m["passwd"] = msg("Changing password for user.\npasswd: Authentication token manipulation error\npasswd: password unchanged\n", 10)
	m["vi"] = msg("Error opening terminal: unknown.\n", 1)
	m["vim"] = msg("Error opening terminal: unknown.\n", 1)
	m["nano"] = msg("Error opening terminal: unknown.\n", 1)
	m["kill"] = cmdKill
	m["pkill"] = msg("", 1)
	m["killall"] = msg("Command 'killall' not found, but can be installed with:\n\nsudo apt install psmisc\n", 127)
	m["nohup"] = msg("nohup: ignoring input and appending output to 'nohup.out'\n", 0)
	m["git"] = msg("fatal: not a git repository (or any of the parent directories): .git\n", 128)
	m["tar"] = cmdTar
	m["gzip"] = cmdGzip
	m["gunzip"] = cmdGzip
	m["openssl"] = func(_ *Shell, a []string, _ string, _ *Result) (string, int) {
		if len(a) > 0 && a[0] == "version" {
			return "OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)\n", 0
		}
		return "", 0
	}

	// network: nothing leaves the box, every attempt times out the way a locked-down host would
	m["ping"] = cmdPing
	m["ssh"] = cmdSSHOut
	m["scp"] = cmdSSHOut
	m["sftp"] = cmdSSHOut
	m["telnet"] = msg("Command 'telnet' not found, but can be installed with:\n\nsudo apt install inetutils-telnet\n", 127)
	m["dig"] = msg(";; communications error to 127.0.0.53#53: timed out\n;; no servers could be reached\n", 9)
	m["nslookup"] = msg(";; communications error to 127.0.0.53#53: timed out\n;; no servers could be reached\n", 1)
	m["host"] = msg(";; communications error to 127.0.0.53#53: timed out\n;; no servers could be reached\n", 1)

	// tools a server like this does not have: Ubuntu's own command-not-found message
	for name, pkg := range notInstalled {
		m[name] = msg(fmt.Sprintf("Command '%s' not found, but can be installed with:\n\nsudo apt install %s\n", name, pkg), 127)
	}
}

var notInstalled = map[string]string{
	"nmap": "nmap", "masscan": "masscan", "tcpdump": "tcpdump", "traceroute": "inetutils-traceroute", "gcc": "gcc",
	"cc": "gcc", "make": "make", "tmux": "tmux", "screen": "screen", "htop": "htop", "jq": "jq", "zip": "zip",
	"unzip": "unzip", "hydra": "hydra", "john": "john", "socat": "socat", "ncat": "ncat", "whois": "whois",
	"ftp": "ftp", "lynx": "lynx", "rsync": "rsync", "mtr": "mtr-tiny", "iftop": "iftop", "nikto": "nikto",
}

func msg(out string, code int) cmdFunc {
	return func(*Shell, []string, string, *Result) (string, int) { return out, code }
}

// ---------- shell features: variables, substitution, loops ----------

var (
	reFor      = regexp.MustCompile(`^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.*?)\s*;\s*do\s+(.*?)\s*;?\s*done\s*$`)
	reWhile    = regexp.MustCompile(`^(.*?)\|\s*while\s+read\s+(?:-r\s+)?([A-Za-z_]\w*)\s*;\s*do\s+(.*?)\s*;?\s*done\s*$`)
	reAssign   = regexp.MustCompile(`^\s*([A-Za-z_]\w*)=(\S*)\s*$`)
	reVarBrace = regexp.MustCompile(`\$\{([A-Za-z_]\w*)(?::-([^}]*))?\}`)
	reVar      = regexp.MustCompile(`\$([A-Za-z_]\w*|\?|\$)`)
)

// runLoop handles `for x in a b; do ...; done` and `cmd | while read l; do ...; done`. ok=false: not a loop.
func (sh *Shell) runLoop(line string) (Result, bool) {
	var items []string
	var name, body string
	if m := reFor.FindStringSubmatch(line); m != nil {
		name, body = m[1], m[3]
		for _, w := range tokenize(sh.expandVars(sh.expandSubst(m[2], 0))) {
			items = append(items, sh.glob(w)...)
		}
	} else if m := reWhile.FindStringSubmatch(line); m != nil {
		name, body = m[2], m[3]
		for _, l := range strings.Split(strings.TrimRight(sh.Run(m[1]).Output, "\n"), "\n") {
			if l != "" {
				items = append(items, l)
			}
		}
	} else {
		return Result{}, false
	}
	var res Result
	var out strings.Builder
	for i, it := range items {
		if i == maxLoopIterations {
			break
		}
		sh.setVar(name, it)
		r := sh.Run(body)
		out.WriteString(r.Output)
		res.Reads = append(res.Reads, r.Reads...)
		res.Exit = r.Exit
		if r.Logout {
			res.Logout = true
			break
		}
	}
	res.Argv0 = map[bool]string{true: "for", false: "while"}[strings.HasPrefix(strings.TrimSpace(line), "for")]
	res.Output = out.String()
	res.StdoutTokens = stdoutTokens(res.Output)
	return res, true
}

// glob expands a trailing * in the last path element against the fake filesystem (for f in /etc/*.conf).
func (sh *Shell) glob(w string) []string {
	if !strings.Contains(w, "*") {
		return []string{w}
	}
	dir, pat := path.Split(w)
	if dir == "" {
		dir = sh.Cwd
	}
	re, err := regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(pat), `\*`, ".*") + "$")
	if err != nil {
		return []string{w}
	}
	var out []string
	for _, n := range sh.FS.List(sh.abs(dir)) {
		if re.MatchString(n.Name) {
			out = append(out, path.Join(strings.TrimSuffix(path.Clean(dir), "/"), n.Name))
		}
	}
	if len(out) == 0 {
		return []string{w}
	}
	return out
}

func (sh *Shell) setVar(k, v string) {
	if sh.vars == nil {
		sh.vars = map[string]string{}
	}
	sh.vars[k] = v
}

func (sh *Shell) getVar(k string) string {
	if v, ok := sh.vars[k]; ok {
		return v
	}
	switch k {
	case "HOME":
		return sh.User.Home
	case "USER", "LOGNAME":
		return sh.User.Name
	case "PWD":
		return sh.Cwd
	case "HOSTNAME":
		return sh.P.Hostname
	case "SHELL":
		return "/bin/bash"
	case "PATH":
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "TERM":
		return "xterm-256color"
	case "?":
		return strconv.Itoa(sh.lastExit)
	case "$":
		return "4021"
	}
	return ""
}

// assignment handles `NAME=value` on its own (bash sets a shell variable, prints nothing).
func (sh *Shell) assignment(seg string) bool {
	m := reAssign.FindStringSubmatch(seg)
	if m == nil {
		return false
	}
	sh.setVar(m[1], strings.Trim(m[2], `"'`))
	return true
}

// expandVars replaces $VAR, ${VAR} and ${VAR:-default} outside single quotes.
func (sh *Shell) expandVars(s string) string {
	return mapOutsideSingleQuotes(s, func(part string) string {
		part = reVarBrace.ReplaceAllStringFunc(part, func(x string) string {
			m := reVarBrace.FindStringSubmatch(x)
			if v := sh.getVar(m[1]); v != "" {
				return v
			}
			return m[2]
		})
		return reVar.ReplaceAllStringFunc(part, func(x string) string { return sh.getVar(x[1:]) })
	})
}

// expandSubst replaces $( ... ) and `...` (outside single quotes) with the emulated output of the inner command.
func (sh *Shell) expandSubst(s string, depth int) string {
	if depth >= maxSubstDepth || (!strings.Contains(s, "$(") && !strings.Contains(s, "`")) {
		return s
	}
	return mapOutsideSingleQuotes(s, func(part string) string {
		var b strings.Builder
		rs := []rune(part)
		for i := 0; i < len(rs); i++ {
			switch {
			case rs[i] == '$' && i+1 < len(rs) && rs[i+1] == '(' && !(i+2 < len(rs) && rs[i+2] == '('):
				lvl, j := 1, i+2
				for ; j < len(rs) && lvl > 0; j++ {
					if rs[j] == '(' {
						lvl++
					} else if rs[j] == ')' {
						lvl--
					}
				}
				if lvl != 0 {
					b.WriteString(string(rs[i:]))
					return b.String()
				}
				b.WriteString(sh.substOutput(string(rs[i+2:j-1]), depth))
				i = j - 1
			case rs[i] == '`':
				j := i + 1
				for j < len(rs) && rs[j] != '`' {
					j++
				}
				if j == len(rs) {
					b.WriteString(string(rs[i:]))
					return b.String()
				}
				b.WriteString(sh.substOutput(string(rs[i+1:j]), depth))
				i = j
			default:
				b.WriteRune(rs[i])
			}
		}
		return b.String()
	})
}

func (sh *Shell) substOutput(cmd string, depth int) string {
	r := sh.run(sh.expandSubst(cmd, depth+1))
	return strings.TrimRight(strings.ReplaceAll(r.Output, "\n", " "), " ")
}

// mapOutsideSingleQuotes applies fn to the parts of s that are not inside '...'.
func mapOutsideSingleQuotes(s string, fn func(string) string) string {
	if !strings.Contains(s, "'") {
		return fn(s)
	}
	var b strings.Builder
	inQ := false
	start := 0
	for i, r := range s {
		if r != '\'' {
			continue
		}
		if inQ {
			b.WriteString(s[start : i+1])
		} else {
			b.WriteString(fn(s[start:i]))
		}
		start, inQ = i, !inQ
		if !inQ {
			start = i + 1
		}
	}
	if inQ {
		b.WriteString(s[start:])
	} else {
		b.WriteString(fn(s[start:]))
	}
	return b.String()
}

// ---------- text tools ----------

// input reads the file arguments (recording file.read for lures) or falls back to stdin.
func (sh *Shell) input(name string, files []string, stdin string, res *Result) (string, string, int) {
	if len(files) == 0 {
		return stdin, "", 0
	}
	var b, errs strings.Builder
	code := 0
	for _, f := range files {
		p := sh.abs(f)
		n := sh.FS.Get(p)
		switch {
		case n == nil:
			fmt.Fprintf(&errs, "%s: %s: No such file or directory\n", name, f)
			code = 1
		case n.Dir:
			fmt.Fprintf(&errs, "%s: %s: Is a directory\n", name, f)
			code = 1
		case len(n.Mode) == 10 && n.Mode[7] == '-' && sh.User.UID != 0 && n.Owner != sh.User.Name:
			fmt.Fprintf(&errs, "%s: %s: Permission denied\n", name, f)
			code = 2
		default:
			b.WriteString(n.Content)
			res.Reads = append(res.Reads, FileRead{Path: p, HoneyfileID: n.HoneyfileID, MazeNode: n.MazeNode, Bytes: len(n.Content)})
		}
	}
	return b.String(), errs.String(), code
}

func lines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func joinLines(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
}

var reSedSub = regexp.MustCompile(`^s(.)(.*?)(?:[^\\])?$`)

func cmdSed(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	quiet := false
	var script string
	var files []string
	for _, a := range args {
		switch {
		case a == "-n":
			quiet = true
		case a == "-e" || a == "-E" || a == "-r" || a == "-i":
		case script == "":
			script = a
		default:
			files = append(files, a)
		}
	}
	if script == "" {
		return "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n", 1
	}
	in, errs, code := sh.input("sed", files, stdin, res)
	ls := lines(in)
	var out []string
	switch {
	case strings.HasPrefix(script, "s") && len(script) > 3:
		d := string(script[1])
		parts := strings.Split(script[2:], d)
		if len(parts) < 2 {
			return "sed: -e expression #1, char " + strconv.Itoa(len(script)) + ": unterminated `s' command\n", 1
		}
		re, err := regexp.Compile(parts[0])
		if err != nil {
			return "sed: -e expression #1: invalid regular expression\n", 1
		}
		global := len(parts) > 2 && strings.Contains(parts[2], "g")
		for _, l := range ls {
			if global {
				l = re.ReplaceAllString(l, parts[1])
			} else if loc := re.FindStringIndex(l); loc != nil {
				l = l[:loc[0]] + re.ReplaceAllString(l[loc[0]:loc[1]], parts[1]) + l[loc[1]:]
			}
			if !quiet {
				out = append(out, l)
			}
		}
	case strings.HasSuffix(script, "p") || strings.HasSuffix(script, "d"):
		addr, op := script[:len(script)-1], script[len(script)-1]
		match := func(i int, l string) bool {
			if n, err := strconv.Atoi(addr); err == nil {
				return i+1 == n
			}
			if a, b, ok := strings.Cut(addr, ","); ok {
				x, _ := strconv.Atoi(a)
				y, err := strconv.Atoi(b)
				if b == "$" {
					y, err = len(ls), nil
				}
				return err == nil && i+1 >= x && i+1 <= y
			}
			if strings.HasPrefix(addr, "/") && strings.HasSuffix(addr, "/") && len(addr) > 1 {
				re, err := regexp.Compile(addr[1 : len(addr)-1])
				return err == nil && re.MatchString(l)
			}
			return addr == ""
		}
		for i, l := range ls {
			m := match(i, l)
			switch {
			case op == 'p' && m:
				out = append(out, l)
				if !quiet {
					out = append(out, l)
				}
			case op == 'p' && !quiet:
				out = append(out, l)
			case op == 'd' && !m:
				out = append(out, l)
			}
		}
	default:
		out = ls
	}
	return errs + joinLines(out), code
}

var reAwkField = regexp.MustCompile(`\$(\d+|NF)`)

func cmdAwk(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	sep := ""
	var prog string
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-F" && i+1 < len(args):
			sep = args[i+1]
			i++
		case strings.HasPrefix(a, "-F"):
			sep = a[2:]
		case prog == "":
			prog = a
		default:
			files = append(files, a)
		}
	}
	if prog == "" {
		return "usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]\n", 2
	}
	in, errs, code := sh.input("awk", files, stdin, res)
	ls := lines(in)
	prog = strings.TrimSpace(prog)
	if strings.HasPrefix(prog, "END") {
		if strings.Contains(prog, "NR") {
			return errs + strconv.Itoa(len(ls)) + "\n", code
		}
		return errs, code
	}
	// optional pattern before the action: /re/ or NR==n
	pattern, action := "", prog
	if i := strings.Index(prog, "{"); i > 0 {
		pattern, action = strings.TrimSpace(prog[:i]), prog[i:]
	} else if !strings.HasPrefix(prog, "{") {
		pattern, action = prog, "{print}"
	}
	action = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(action, "{"), "}"))
	var out []string
	for n, l := range ls {
		if !awkMatch(pattern, n+1, l) {
			continue
		}
		var fields []string
		if sep == "" {
			fields = strings.Fields(l)
		} else {
			fields = strings.Split(l, strings.ReplaceAll(sep, `\t`, "\t"))
		}
		if !strings.HasPrefix(action, "print") {
			continue
		}
		expr := strings.TrimSpace(strings.TrimPrefix(action, "print"))
		if expr == "" || expr == "$0" {
			out = append(out, l)
			continue
		}
		var parts []string
		for _, item := range strings.Split(expr, ",") {
			item = strings.TrimSpace(item)
			parts = append(parts, reAwkField.ReplaceAllStringFunc(strings.Trim(item, `"`), func(f string) string {
				if f == "$NF" {
					if len(fields) == 0 {
						return ""
					}
					return fields[len(fields)-1]
				}
				k, _ := strconv.Atoi(f[1:])
				if k == 0 {
					return l
				}
				if k <= len(fields) {
					return fields[k-1]
				}
				return ""
			}))
		}
		out = append(out, strings.Join(parts, " "))
	}
	return errs + joinLines(out), code
}

func awkMatch(pattern string, nr int, l string) bool {
	switch {
	case pattern == "":
		return true
	case strings.HasPrefix(pattern, "NR=="):
		n, _ := strconv.Atoi(strings.TrimPrefix(pattern, "NR=="))
		return n == nr
	case strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") && len(pattern) > 1:
		re, err := regexp.Compile(pattern[1 : len(pattern)-1])
		return err == nil && re.MatchString(l)
	}
	return true
}

func cmdSort(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	var rev, num, uniq bool
	var files []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			rev = rev || strings.Contains(a, "r")
			num = num || strings.Contains(a, "n")
			uniq = uniq || strings.Contains(a, "u")
			continue
		}
		files = append(files, a)
	}
	in, errs, code := sh.input("sort", files, stdin, res)
	ls := lines(in)
	sort.SliceStable(ls, func(i, j int) bool {
		if num {
			a, _ := strconv.ParseFloat(strings.Fields(ls[i] + " 0")[0], 64)
			b, _ := strconv.ParseFloat(strings.Fields(ls[j] + " 0")[0], 64)
			if a != b {
				return (a < b) != rev
			}
		}
		return (ls[i] < ls[j]) != rev
	})
	if uniq {
		ls = dedupe(ls, false)
	}
	return errs + joinLines(ls), code
}

func dedupe(ls []string, counts bool) []string {
	var out []string
	for i := 0; i < len(ls); {
		j := i
		for j < len(ls) && ls[j] == ls[i] {
			j++
		}
		if counts {
			out = append(out, fmt.Sprintf("%7d %s", j-i, ls[i]))
		} else {
			out = append(out, ls[i])
		}
		i = j
	}
	return out
}

func cmdUniq(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	counts := false
	var files []string
	for _, a := range args {
		if a == "-c" {
			counts = true
		} else if !strings.HasPrefix(a, "-") {
			files = append(files, a)
		}
	}
	in, errs, code := sh.input("uniq", files, stdin, res)
	return errs + joinLines(dedupe(lines(in), counts)), code
}

func cmdCut(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	delim, fieldSpec := "\t", ""
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-d" && i+1 < len(args):
			delim, i = args[i+1], i+1
		case strings.HasPrefix(a, "-d"):
			delim = a[2:]
		case a == "-f" && i+1 < len(args):
			fieldSpec, i = args[i+1], i+1
		case strings.HasPrefix(a, "-f"):
			fieldSpec = a[2:]
		case !strings.HasPrefix(a, "-"):
			files = append(files, a)
		}
	}
	if fieldSpec == "" {
		return "cut: you must specify a list of bytes, characters, or fields\n", 1
	}
	want := map[int]bool{}
	for _, f := range strings.Split(fieldSpec, ",") {
		if a, b, ok := strings.Cut(f, "-"); ok {
			x, _ := strconv.Atoi(a)
			y, err := strconv.Atoi(b)
			if err != nil {
				y = 64
			}
			for k := max(x, 1); k <= y; k++ {
				want[k] = true
			}
		} else if k, err := strconv.Atoi(f); err == nil {
			want[k] = true
		}
	}
	in, errs, code := sh.input("cut", files, stdin, res)
	var out []string
	for _, l := range lines(in) {
		fs := strings.Split(l, delim)
		var keep []string
		for i, f := range fs {
			if want[i+1] {
				keep = append(keep, f)
			}
		}
		out = append(out, strings.Join(keep, delim))
	}
	return errs + joinLines(out), code
}

func cmdTr(_ *Shell, args []string, stdin string, _ *Result) (string, int) {
	var del bool
	var sets []string
	for _, a := range args {
		if a == "-d" {
			del = true
		} else if !strings.HasPrefix(a, "-") {
			sets = append(sets, a)
		}
	}
	expand := func(s string) []rune {
		switch s {
		case "a-z", "[:lower:]":
			return []rune("abcdefghijklmnopqrstuvwxyz")
		case "A-Z", "[:upper:]":
			return []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		}
		return []rune(strings.NewReplacer(`\n`, "\n", `\t`, "\t").Replace(s))
	}
	if len(sets) == 0 {
		return "tr: missing operand\n", 1
	}
	from := expand(sets[0])
	return strings.Map(func(r rune) rune {
		for i, f := range from {
			if r == f {
				if del {
					return -1
				}
				if len(sets) > 1 {
					to := expand(sets[1])
					if len(to) > 0 {
						return to[min(i, len(to)-1)]
					}
				}
			}
		}
		return r
	}, stdin), 0
}

func cmdTee(sh *Shell, args []string, stdin string, _ *Result) (string, int) {
	appendTo := false
	for _, a := range args {
		if a == "-a" {
			appendTo = true
			continue
		}
		if !strings.HasPrefix(a, "-") && !sh.FS.Write(sh.abs(a), stdin, sh.User.Name, appendTo) {
			return stdin + "tee: " + a + ": Permission denied\n", 1
		}
	}
	return stdin, 0
}

func cmdXargs(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	cmd := []string{"echo"}
	if len(args) > 0 {
		cmd = args
	}
	words := strings.Fields(stdin)
	if len(words) > 200 {
		words = words[:200]
	}
	return sh.exec(append(append([]string{}, cmd...), words...), "", res)
}

func cmdBase64(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	decode := false
	var files []string
	for _, a := range args {
		if a == "-d" || a == "--decode" {
			decode = true
		} else if !strings.HasPrefix(a, "-") {
			files = append(files, a)
		}
	}
	in, errs, code := sh.input("base64", files, stdin, res)
	if code != 0 {
		return errs, code
	}
	if decode {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(in), ""))
		if err != nil {
			return string(b) + "base64: invalid input\n", 1
		}
		return string(b), 0
	}
	enc := base64.StdEncoding.EncodeToString([]byte(in))
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\n")
	return b.String(), 0
}

func hashCmd(kind string) cmdFunc {
	return func(sh *Shell, args []string, stdin string, res *Result) (string, int) {
		sum := func(s string) string {
			switch kind {
			case "md5":
				return fmt.Sprintf("%x", md5.Sum([]byte(s)))
			case "sha1":
				return fmt.Sprintf("%x", sha1.Sum([]byte(s)))
			}
			return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
		}
		if len(args) == 0 {
			return sum(stdin) + "  -\n", 0
		}
		var b strings.Builder
		code := 0
		for _, f := range args {
			in, errs, c := sh.input(kind+"sum", []string{f}, "", res)
			if c != 0 {
				b.WriteString(errs)
				code = c
				continue
			}
			fmt.Fprintf(&b, "%s  %s\n", sum(in), f)
		}
		return b.String(), code
	}
}

func cmdRev(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	in, errs, code := sh.input("rev", args, stdin, res)
	var out []string
	for _, l := range lines(in) {
		r := []rune(l)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		out = append(out, string(r))
	}
	return errs + joinLines(out), code
}

func cmdNl(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	in, errs, code := sh.input("nl", args, stdin, res)
	var out []string
	n := 0
	for _, l := range lines(in) {
		if strings.TrimSpace(l) == "" {
			out = append(out, l)
			continue
		}
		n++
		out = append(out, fmt.Sprintf("%6d\t%s", n, l))
	}
	return errs + joinLines(out), code
}

func cmdSeq(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	nums := []int{}
	for _, a := range args {
		n, err := strconv.Atoi(a)
		if err != nil {
			return fmt.Sprintf("seq: invalid floating point argument: '%s'\n", a), 1
		}
		nums = append(nums, n)
	}
	first, step, last := 1, 1, 0
	switch len(nums) {
	case 1:
		last = nums[0]
	case 2:
		first, last = nums[0], nums[1]
	case 3:
		first, step, last = nums[0], nums[1], nums[2]
	default:
		return "seq: missing operand\n", 1
	}
	if step == 0 {
		return "seq: invalid Zero increment value: '0'\n", 1
	}
	var out []string
	for i := first; (step > 0 && i <= last) || (step < 0 && i >= last); i += step {
		out = append(out, strconv.Itoa(i))
		if len(out) == 10000 {
			break
		}
	}
	return joinLines(out), 0
}

func cmdRealpath(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, sh.abs(a))
		}
	}
	return joinLines(out), 0
}

func cmdStat(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	code := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		n := sh.FS.Get(sh.abs(a))
		if n == nil {
			fmt.Fprintf(&b, "stat: cannot statx '%s': No such file or directory\n", a)
			code = 1
			continue
		}
		kind, size := "regular file", len(n.Content)
		if n.Dir {
			kind, size = "directory", 4096
		}
		mode := n.Mode
		if mode == "" {
			mode = "-rw-r--r--"
		}
		fmt.Fprintf(&b, "  File: %s\n  Size: %-10d\tBlocks: 8          IO Block: 4096   %s\nDevice: 803h/2051d\tInode: %d   Links: 1\n"+
			"Access: (0%s/%s)  Uid: ( 1001/%8s)   Gid: ( 1001/%8s)\nModify: %s\n",
			a, size, kind, 400000+len(a)*37, octal(mode), mode, n.Owner, n.Owner, n.ModTime.Format("2006-01-02 15:04:05.000000000 -0700"))
	}
	return b.String(), code
}

func octal(mode string) string {
	if len(mode) != 10 {
		return "644"
	}
	d := func(s string) int {
		v := 0
		if s[0] == 'r' {
			v += 4
		}
		if s[1] == 'w' {
			v += 2
		}
		if s[2] == 'x' {
			v++
		}
		return v
	}
	return fmt.Sprintf("%d%d%d", d(mode[1:4]), d(mode[4:7]), d(mode[7:10]))
}

func cmdFile(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		n := sh.FS.Get(sh.abs(a))
		switch {
		case n == nil:
			fmt.Fprintf(&b, "%s: cannot open `%s' (No such file or directory)\n", a, a)
		case n.Dir:
			fmt.Fprintf(&b, "%s: directory\n", a)
		case strings.HasPrefix(n.Content, "#!/bin/bash") || strings.HasPrefix(n.Content, "#!/bin/sh"):
			fmt.Fprintf(&b, "%s: Bourne-Again shell script, ASCII text executable\n", a)
		case strings.HasPrefix(n.Content, "-----BEGIN"):
			fmt.Fprintf(&b, "%s: PEM RSA private key\n", a)
		case strings.HasSuffix(a, ".gz") || strings.HasSuffix(a, ".zip"):
			fmt.Fprintf(&b, "%s: gzip compressed data\n", a)
		case n.Content == "":
			fmt.Fprintf(&b, "%s: empty\n", a)
		default:
			fmt.Fprintf(&b, "%s: ASCII text\n", a)
		}
	}
	return b.String(), 0
}

func cmdDu(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	target := "."
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	total := 0
	var walk func(p string)
	walk = func(p string) {
		for _, n := range sh.FS.List(p) {
			if n.Dir {
				walk(path.Join(p, n.Name))
			} else {
				total += len(n.Content)
			}
		}
	}
	walk(sh.abs(target))
	kb := total/1024 + 4
	if strings.Contains(strings.Join(args, " "), "h") {
		return fmt.Sprintf("%dK\t%s\n", kb, target), 0
	}
	return fmt.Sprintf("%d\t%s\n", kb, target), 0
}

func cmdTest(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) > 0 && args[len(args)-1] == "]" {
		args = args[:len(args)-1]
	}
	if len(args) == 2 {
		n := sh.FS.Get(sh.abs(args[1]))
		ok := false
		switch args[0] {
		case "-f":
			ok = n != nil && !n.Dir
		case "-d":
			ok = n != nil && n.Dir
		case "-e", "-r":
			ok = n != nil
		case "-z":
			ok = args[1] == ""
		case "-n":
			ok = args[1] != ""
		}
		if ok {
			return "", 0
		}
		return "", 1
	}
	if len(args) == 3 && (args[1] == "=" || args[1] == "==") {
		if args[0] == args[2] {
			return "", 0
		}
	}
	return "", 1
}

// ---------- system views ----------

func cmdLsof(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	u := sh.User.Name
	return "COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME\n" +
		fmt.Sprintf("bash    4021 %-6s cwd    DIR    8,3     4096 393217 %s\n", u, sh.User.Home) +
		fmt.Sprintf("bash    4021 %-6s rtd    DIR    8,3     4096      2 /\n", u) +
		fmt.Sprintf("bash    4021 %-6s txt    REG    8,3  1396520 131243 /usr/bin/bash\n", u) +
		fmt.Sprintf("bash    4021 %-6s   0u   CHR  136,0      0t0      3 /dev/pts/0\n", u), 0
}

var units = []struct{ name, desc string }{
	{"ssh.service", "OpenBSD Secure Shell server"}, {"nginx.service", "A high performance web server and a reverse proxy server"},
	{"docker.service", "Docker Application Container Engine"}, {"containerd.service", "containerd container runtime"},
	{"cron.service", "Regular background program processing daemon"}, {"rsyslog.service", "System Logging Service"},
	{"systemd-journald.service", "Journal Service"}, {"ufw.service", "Uncomplicated firewall"},
}

func cmdSystemctl(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) == 0 || args[0] == "list-units" || strings.HasPrefix(args[0], "--") {
		var b strings.Builder
		b.WriteString("  UNIT                      LOAD   ACTIVE SUB     DESCRIPTION\n")
		for _, u := range units {
			fmt.Fprintf(&b, "  %-25s loaded active running %s\n", u.name, u.desc)
		}
		fmt.Fprintf(&b, "\n%d loaded units listed.\n", len(units))
		return b.String(), 0
	}
	verb := args[0]
	unit := ""
	if len(args) > 1 {
		unit = args[1]
		if !strings.Contains(unit, ".") {
			unit += ".service"
		}
	}
	switch verb {
	case "status":
		for _, u := range units {
			if u.name == unit {
				return fmt.Sprintf("● %s - %s\n     Loaded: loaded (/lib/systemd/system/%s; enabled; vendor preset: enabled)\n"+
					"     Active: active (running) since %s; 3 days ago\n   Main PID: %d\n",
					u.name, u.desc, u.name, sh.Started.AddDate(0, 0, -3).Format("Mon 2006-01-02 15:04:05 MST"), 800+len(u.name)*13), 0
			}
		}
		return fmt.Sprintf("Unit %s could not be found.\n", unit), 4
	case "start", "stop", "restart", "enable", "disable", "daemon-reload", "kill", "mask":
		return "Failed to " + verb + " " + unit + ": Interactive authentication required.\nSee system logs and 'systemctl status " + unit + "' for details.\n", 1
	case "is-active":
		return "active\n", 0
	}
	return "Unknown command verb " + verb + ".\n", 1
}

func cmdService(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	if len(args) > 0 && args[0] == "--status-all" {
		var b strings.Builder
		for _, n := range []string{"apparmor", "cron", "dbus", "docker", "nginx", "procps", "rsyslog", "ssh", "ufw"} {
			fmt.Fprintf(&b, " [ + ]  %s\n", n)
		}
		return b.String(), 0
	}
	if len(args) >= 2 {
		return cmdSystemctl(sh, []string{args[1], args[0]}, stdin, res)
	}
	return "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n", 1
}

func cmdLsblk(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\nloop0    7:0    0 63.9M  1 loop /snap/core20/2318\nsda      8:0    0   80G  0 disk \n" +
		"├─sda1   8:1    0    1M  0 part \n├─sda2   8:2    0    2G  0 part /boot\n└─sda3   8:3    0   78G  0 part /\n", 0
}

func cmdLscpu(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\nCPU(s):                  4\n" +
		"Vendor ID:               GenuineIntel\n  Model name:            Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n" +
		"    Thread(s) per core:  2\nVirtualization features:\n  Hypervisor vendor:     KVM\n", 0
}

func cmdMount(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "/dev/sda3 on / type ext4 (rw,relatime)\n/dev/sda2 on /boot type ext4 (rw,relatime)\n" +
		"proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\ntmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=401424k)\n" +
		"overlay on /var/lib/docker/overlay2/3f1c/merged type overlay (rw,relatime)\n", 0
}

func cmdGetent(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	if len(args) == 0 {
		return "Usage: getent [OPTION...] database [key ...]\n", 1
	}
	file := map[string]string{"passwd": "/etc/passwd", "group": "/etc/group", "hosts": "/etc/hosts"}[args[0]]
	if file == "" {
		return "Unknown database: " + args[0] + "\n", 1
	}
	in, _, _ := sh.input("getent", []string{file}, stdin, res)
	if len(args) == 1 {
		return in, 0
	}
	var out []string
	for _, l := range lines(in) {
		if strings.HasPrefix(l, args[1]+":") || strings.Contains(" "+l+" ", " "+args[1]+" ") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return "", 2
	}
	return joinLines(out), 0
}

func cmdLast(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	t := sh.Started
	return fmt.Sprintf("%-8s pts/0        10.0.0.1         %s   still logged in\n", sh.User.Name, t.Format("Mon Jan  2 15:04")) +
		fmt.Sprintf("%-8s pts/1        10.0.4.17        %s - %s  (01:12)\n", sh.User.Name, t.AddDate(0, 0, -1).Format("Mon Jan  2 15:04"),
			t.AddDate(0, 0, -1).Add(72*60e9).Format("15:04")) +
		fmt.Sprintf("reboot   system boot  5.15.0-109-gener %s   still running\n\nwtmp begins %s\n",
			t.AddDate(0, 0, -3).Format("Mon Jan  2 15:04"), t.AddDate(0, -1, 0).Format("Mon Jan  2 15:04:05 2006")), 0
}

func cmdLastlog(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "Username         Port     From             Latest\nroot                                       **Never logged in**\n" +
		fmt.Sprintf("%-16s pts/0    10.0.0.1         %s\n", sh.User.Name, sh.Started.Format("Mon Jan  2 15:04:05 -0700 2006")), 0
}

func cmdType(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	code := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		switch {
		case a == "cd" || a == "echo" || a == "export" || a == "history" || a == "alias" || a == "type":
			fmt.Fprintf(&b, "%s is a shell builtin\n", a)
		default:
			if _, ok := commands[a]; ok {
				if _, missing := notInstalled[a]; !missing {
					fmt.Fprintf(&b, "%s is /usr/bin/%s\n", a, a)
					continue
				}
			}
			fmt.Fprintf(&b, "bash: type: %s: not found\n", a)
			code = 1
		}
	}
	return b.String(), code
}

func cmdApt(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) > 0 && (args[0] == "list" || args[0] == "show" || args[0] == "search" || args[0] == "policy") {
		return "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n" +
			"Listing... Done\nopenssh-server/jammy-updates,now 1:8.9p1-3ubuntu0.10 amd64 [installed]\n" +
			"nginx/jammy-updates,now 1.18.0-6ubuntu14.4 all [installed]\ndocker-ce/jammy,now 5:24.0.7-1~ubuntu.22.04~jammy amd64 [installed]\n", 0
	}
	return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n" +
		"E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n", 100
}

func cmdDpkg(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) > 0 && (args[0] == "-l" || args[0] == "--list") {
		return "Desired=Unknown/Install/Remove/Purge/Hold\n||/ Name            Version                     Architecture Description\n" +
			"+++-===============-===========================-============-=================================\n" +
			"ii  docker-ce       5:24.0.7-1~ubuntu.22.04     amd64        Docker: the open-source application container engine\n" +
			"ii  nginx           1.18.0-6ubuntu14.4          all          small, powerful, scalable web/proxy server\n" +
			"ii  openssh-server  1:8.9p1-3ubuntu0.10         amd64        secure shell (SSH) server, for secure access from remote machines\n", 0
	}
	return "dpkg: error: requested operation requires superuser privilege\n", 2
}

func cmdKill(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if n, err := strconv.Atoi(a); err == nil && n < 4000 {
			return fmt.Sprintf("bash: kill: (%d) - Operation not permitted\n", n), 1
		}
		return fmt.Sprintf("bash: kill: (%s) - No such process\n", a), 1
	}
	return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n", 2
}

func cmdTar(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) == 0 {
		return "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\nTry 'tar --help' or 'tar --usage' for more information.\n", 2
	}
	return "tar: Cannot open: Permission denied\ntar: Error is not recoverable: exiting now\n", 2
}

func cmdGzip(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return "gzip: " + a + ": not in gzip format\n", 1
		}
	}
	return "gzip: compressed data not written to a terminal. Use -f to force compression.\n", 1
}

// ---------- network (nothing leaves the decoy) ----------

func cmdPing(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	host := ""
	count := 4
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-c" && i+1 < len(args):
			count, _ = strconv.Atoi(args[i+1])
			i++
		case !strings.HasPrefix(args[i], "-"):
			host = args[i]
		}
	}
	if host == "" {
		return "ping: usage error: Destination address required\n", 1
	}
	if !isIPv4Literal(host) {
		return "ping: " + host + ": Temporary failure in name resolution\n", 2
	}
	if count <= 0 || count > 10 {
		count = 4
	}
	return fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\n\n--- %s ping statistics ---\n%d packets transmitted, 0 received, 100%% packet loss, time %dms\n\n",
		host, host, host, count, (count-1)*1000+23), 1
}

func cmdSSHOut(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	host := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			host = a
			break
		}
	}
	if host == "" {
		return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] destination [command]\n", 255
	}
	if _, h, ok := strings.Cut(host, "@"); ok {
		host = h
	}
	host, _, _ = strings.Cut(host, ":")
	return "ssh: connect to host " + host + " port 22: Connection timed out\n", 255
}
