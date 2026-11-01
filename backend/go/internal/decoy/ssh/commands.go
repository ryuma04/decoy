package ssh

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/fakefs"
	"github.com/ryuma04/decoy/backend/internal/persona"
)

// FileRead is reported as a file.read event.
type FileRead struct {
	Path        string
	HoneyfileID string
	MazeNode    string
	Bytes       int
}

// Result of one shell line.
type Result struct {
	Output       string
	Exit         int
	Argv0        string
	Args         []string
	Reads        []FileRead
	Logout       bool
	Clear        bool
	StdoutTokens []string
	// SecretPrompt: the command asked for a password (sudo / su); the server shows this prompt with echo off
	// and passes the next line to Shell.AnswerPassword instead of running it.
	SecretPrompt string
}

// Shell emulates bash over a fake filesystem. Commands are Go functions; nothing real is ever run.
type Shell struct {
	FS          *fakefs.FS
	P           persona.Persona
	User        persona.User
	Cwd         string
	History     func() []string
	Started     time.Time
	Interactive bool // a pty shell (password prompts possible); false for `ssh host cmd`
	pending     *pendingAuth
	vars        map[string]string // shell variables (NAME=value, export, loop variables)
	lastExit    int               // $?
}

// pendingAuth is a password prompt waiting for input. Every answer fails: the decoy has no real privilege.
type pendingAuth struct {
	kind  string // "sudo" | "su"
	tries int    // answers left
}

// PasswordPending reports whether the next input line is a password answer.
func (sh *Shell) PasswordPending() bool { return sh.pending != nil }

// AnswerPassword consumes one typed password. sudo allows 3 tries ("Sorry, try again."), su one.
func (sh *Shell) AnswerPassword(_ string) Result {
	p := sh.pending
	if p == nil {
		return Result{}
	}
	p.tries--
	if p.kind == "su" {
		sh.pending = nil
		return Result{Output: "su: Authentication failure\n", Exit: 1, Argv0: "su"}
	}
	if p.tries > 0 {
		return Result{Output: "Sorry, try again.\n", Exit: 1, Argv0: "sudo", SecretPrompt: sh.sudoPrompt()}
	}
	sh.pending = nil
	return Result{Output: "sudo: 3 incorrect password attempts\n", Exit: 1, Argv0: "sudo"}
}

func (sh *Shell) sudoPrompt() string { return "[sudo] password for " + sh.User.Name + ": " }

// CancelPassword aborts a pending password prompt.
func (sh *Shell) CancelPassword() {
	sh.pending = nil
}

type cmdFunc func(sh *Shell, args []string, stdin string, res *Result) (string, int)

var commands map[string]cmdFunc

func init() {
	commands = map[string]cmdFunc{
		"whoami":   func(sh *Shell, _ []string, _ string, _ *Result) (string, int) { return sh.User.Name + "\n", 0 },
		"id":       cmdID,
		"hostname": func(sh *Shell, _ []string, _ string, _ *Result) (string, int) { return sh.P.Hostname + "\n", 0 },
		"uname":    cmdUname,
		"pwd":      func(sh *Shell, _ []string, _ string, _ *Result) (string, int) { return sh.Cwd + "\n", 0 },
		"ls":       cmdLs,
		"cd":       cmdCd,
		"cat":      cmdCat,
		"echo":     cmdEcho,
		"history":  cmdHistory,
		"true":     func(*Shell, []string, string, *Result) (string, int) { return "", 0 },
		"false":    func(*Shell, []string, string, *Result) (string, int) { return "", 1 },
		"clear":    func(_ *Shell, _ []string, _ string, r *Result) (string, int) { r.Clear = true; return "", 0 },
		"exit":     func(_ *Shell, _ []string, _ string, r *Result) (string, int) { r.Logout = true; return "", 0 },
		"logout":   func(_ *Shell, _ []string, _ string, r *Result) (string, int) { r.Logout = true; return "", 0 },
	}
	registerExtra(commands)
	registerMore(commands)
}

// Run executes one command line: `;`, `&&`, `||` and `|` are split and emulated in order.
// Run emulates one shell line: loops, $( ) / backtick substitution, then ; && || | segments with variables expanded.
func (sh *Shell) Run(line string) Result {
	if r, ok := sh.runLoop(line); ok {
		sh.lastExit = r.Exit
		return r
	}
	r := sh.run(sh.expandSubst(line, 0))
	sh.lastExit = r.Exit
	return r
}

func (sh *Shell) run(line string) Result {
	var res Result
	segs := splitOps(line)
	var out strings.Builder
	exit := 0
	stdin := ""
	for i, s := range segs {
		if i > 0 {
			switch segs[i-1].op {
			case "&&":
				if exit != 0 {
					continue
				}
			case "||":
				if exit == 0 {
					continue
				}
			}
		}
		if sh.assignment(s.text) {
			exit = 0
			continue
		}
		argv := dropStderrRedirects(tokenize(sh.expandVars(s.text)))
		if len(argv) == 0 {
			continue
		}
		argv, redirect, appendMode := takeRedirect(argv)
		if res.Argv0 == "" {
			res.Argv0, res.Args = path.Base(argv[0]), argv[1:]
		}
		o, code := sh.exec(argv, stdin, &res)
		exit = code
		sh.lastExit = code // $? for the next segment of the same line
		if redirect != "" {
			if !sh.FS.Write(sh.abs(redirect), o, sh.User.Name, appendMode) {
				out.WriteString("bash: " + redirect + ": No such file or directory\n")
				exit = 1
			}
			o = ""
		}
		if s.op == "|" {
			stdin = o
			continue
		}
		stdin = ""
		out.WriteString(o)
		if res.Logout {
			break
		}
	}
	res.Output, res.Exit = out.String(), exit
	res.StdoutTokens = stdoutTokens(res.Output)
	return res
}

func (sh *Shell) exec(argv []string, stdin string, res *Result) (string, int) {
	name := path.Base(argv[0])
	if fn, ok := commands[name]; ok {
		return fn(sh, argv[1:], stdin, res)
	}
	return "bash: " + argv[0] + ": command not found\n", 127
}

func (sh *Shell) abs(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = sh.User.Home + strings.TrimPrefix(p, "~")
	}
	return fakefs.Clean(sh.Cwd, p)
}

// ---------- commands ----------

func cmdID(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	u := sh.User
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		var ok bool
		if u, ok = sh.P.User(args[0]); !ok {
			return "id: '" + args[0] + "': no such user\n", 1
		}
	}
	groups := fmt.Sprintf("%d(%s)", u.UID, u.Name)
	if u.UID == 0 {
		groups = "0(root)"
	} else if u.Name == "deploy" {
		groups += ",27(sudo),999(docker)"
	}
	return fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%s\n", u.UID, u.Name, u.UID, u.Name, groups), 0
}

func cmdUname(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	flags := strings.Join(args, "")
	switch {
	case strings.Contains(flags, "a"):
		return fmt.Sprintf("Linux %s %s #%d-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n", sh.P.Hostname, sh.P.Kernel, 90), 0
	case strings.Contains(flags, "r"):
		return sh.P.Kernel + "\n", 0
	case strings.Contains(flags, "n"):
		return sh.P.Hostname + "\n", 0
	case strings.Contains(flags, "m"):
		return "x86_64\n", 0
	}
	return "Linux\n", 0
}

func cmdLs(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	long, all := false, false
	var targets []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			long = long || strings.Contains(a, "l")
			all = all || strings.Contains(a, "a")
			continue
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	var out strings.Builder
	exit := 0
	for _, t := range targets {
		p := sh.abs(t)
		n := sh.FS.Get(p)
		if n == nil {
			fmt.Fprintf(&out, "ls: cannot access '%s': No such file or directory\n", t)
			exit = 2
			continue
		}
		if len(targets) > 1 && n.Dir {
			fmt.Fprintf(&out, "%s:\n", t)
		}
		entries := []*fakefs.Node{n}
		if n.Dir {
			entries = nil
			for _, c := range sh.FS.List(p) {
				if all || !strings.HasPrefix(c.Name, ".") {
					entries = append(entries, c)
				}
			}
		}
		if long {
			fmt.Fprintf(&out, "total %d\n", 4*len(entries))
			for _, c := range entries {
				size := len(c.Content)
				if c.Dir {
					size = 4096
				}
				owner := c.Owner
				if owner == "" {
					owner = "root"
				}
				mt := c.ModTime
				if mt.IsZero() {
					mt = sh.Started.Add(-72 * time.Hour)
				}
				fmt.Fprintf(&out, "%s 1 %-8s %-8s %6d %s %s\n", c.Mode, owner, owner, size, mt.Format("Jan _2 15:04"), c.Name)
			}
		} else {
			names := make([]string, 0, len(entries))
			for _, c := range entries {
				names = append(names, c.Name)
			}
			if len(names) > 0 {
				out.WriteString(strings.Join(names, "  ") + "\n")
			}
		}
	}
	return out.String(), exit
}

func cmdCd(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	target := sh.User.Home
	if len(args) > 0 && args[0] != "~" {
		target = args[0]
	}
	p := sh.abs(target)
	n := sh.FS.Get(p)
	if n == nil {
		return "bash: cd: " + target + ": No such file or directory\n", 1
	}
	if !n.Dir {
		return "bash: cd: " + target + ": Not a directory\n", 1
	}
	sh.Cwd = p
	return "", 0
}

func cmdCat(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	if len(args) == 0 {
		return stdin, 0
	}
	var out strings.Builder
	exit := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := sh.abs(a)
		n := sh.FS.Get(p)
		switch {
		case n == nil:
			fmt.Fprintf(&out, "cat: %s: No such file or directory\n", a)
			exit = 1
		case n.Dir:
			fmt.Fprintf(&out, "cat: %s: Is a directory\n", a)
			exit = 1
		case len(n.Mode) == 10 && n.Mode[7] == '-' && sh.User.UID != 0 && n.Owner != sh.User.Name: // others can't read
			fmt.Fprintf(&out, "cat: %s: Permission denied\n", a)
			exit = 1
		default:
			out.WriteString(n.Content)
			res.Reads = append(res.Reads, FileRead{Path: p, HoneyfileID: n.HoneyfileID, MazeNode: n.MazeNode, Bytes: len(n.Content)})
		}
	}
	return out.String(), exit
}

func cmdEcho(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) > 0 && args[0] == "-n" {
		return strings.Join(args[1:], " "), 0
	}
	return strings.Join(args, " ") + "\n", 0
}

func cmdHistory(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	var out strings.Builder
	h := sh.History()
	for i, l := range h {
		fmt.Fprintf(&out, "%5d  %s\n", i+1, l)
	}
	return out.String(), 0
}

// ---------- parsing ----------

type segment struct {
	text string
	op   string // operator that FOLLOWS this segment: ; && || | or ""
}

// splitOps splits on ; && || | outside quotes.
func splitOps(line string) []segment {
	var segs []segment
	var cur strings.Builder
	var quote rune
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			cur.WriteRune(r)
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
			cur.WriteRune(r)
		case r == ';':
			segs = append(segs, segment{cur.String(), ";"})
			cur.Reset()
		case (r == '&' || r == '|') && i+1 < len(rs) && rs[i+1] == r:
			segs = append(segs, segment{cur.String(), string([]rune{r, r})})
			cur.Reset()
			i++
		case r == '|':
			segs = append(segs, segment{cur.String(), "|"})
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(segs, segment{cur.String(), ""})
}

// tokenize splits words, honouring single and double quotes and backslash escapes. No expansion.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// dropStderrRedirects removes `2>/dev/null`, `2>&1`, `2> file`, `&>file`: stderr is merged into the output anyway.
func dropStderrRedirects(argv []string) []string {
	out := argv[:0:0]
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "2>" || a == "2>>" || a == "&>":
			i++ // skip the target word
		case strings.HasPrefix(a, "2>") || strings.HasPrefix(a, "&>"):
		default:
			out = append(out, a)
		}
	}
	return out
}

func takeRedirect(argv []string) ([]string, string, bool) {
	for i, a := range argv {
		if (a == ">" || a == ">>") && i+1 < len(argv) {
			return append(argv[:i:i], argv[i+2:]...), argv[i+1], a == ">>"
		}
		if strings.HasPrefix(a, ">>") && len(a) > 2 {
			return append(argv[:i:i], argv[i+1:]...), a[2:], true
		}
		if strings.HasPrefix(a, ">") && len(a) > 1 {
			return append(argv[:i:i], argv[i+1:]...), a[1:], false
		}
	}
	return argv, "", false
}

var tokenRe = regexp.MustCompile(`[A-Za-z0-9._/~-]{2,}`)

// stdoutTokens keeps up to 50 path-like or word tokens of the simulated output (02, output dependence).
func stdoutTokens(out string) []string {
	seen := map[string]bool{}
	var toks []string
	for _, t := range tokenRe.FindAllString(out, -1) {
		if !seen[t] {
			seen[t] = true
			toks = append(toks, t)
			if len(toks) == 50 {
				break
			}
		}
	}
	sort.Strings(toks)
	return toks
}
