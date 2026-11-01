package ssh

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

func registerExtra(m map[string]cmdFunc) {
	// System info
	m["ps"] = cmdPs
	m["top"] = cmdTop
	m["w"] = cmdW
	m["uptime"] = cmdUptime
	m["date"] = cmdDate
	m["df"] = cmdDf
	m["free"] = cmdFree
	m["env"] = cmdEnv
	m["printenv"] = cmdEnv
	m["netstat"] = cmdNetstat
	m["ss"] = cmdSS
	m["ip"] = cmdIP
	m["ifconfig"] = cmdIfconfig
	m["which"] = cmdWhich

	// Files over fakefs
	m["find"] = cmdFind
	m["grep"] = cmdGrep
	m["head"] = cmdHead
	m["tail"] = cmdTail
	m["wc"] = cmdWc

	// Overlay changes
	m["touch"] = cmdTouch
	m["mkdir"] = cmdMkdir
	m["rm"] = cmdRm
	m["cp"] = cmdCp
	m["mv"] = cmdMv
	m["chmod"] = cmdChmod
	m["chown"] = cmdChown

	// Network simulators
	m["wget"] = cmdWget
	m["curl"] = cmdCurl

	// Auth & privilege
	m["sudo"] = cmdSudo
	m["su"] = cmdSu

	// Services & tools
	m["mysql"] = cmdMysql
	m["psql"] = cmdPsql
	m["kubectl"] = cmdKubectl
	m["docker"] = cmdDocker
	m["crontab"] = cmdCrontab
	m["python"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
	m["python3"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
	m["perl"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
	m["bash"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
	m["sh"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
	m["nc"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
	m["export"] = cmdExport
	m["alias"] = cmdAlias
	m["sleep"] = func(*Shell, []string, string, *Result) (string, int) { return "", 0 }
}

// ---------- System Info ----------

func cmdPs(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	flags := strings.Join(args, " ")
	u := sh.User.Name
	switch {
	case strings.Contains(flags, "u"): // ps aux, ps -u
		var b strings.Builder
		b.WriteString("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
		b.WriteString("root           1  0.0  0.2 168420 12480 ?        Ss   10:00   0:02 /sbin/init\n")
		b.WriteString("root           2  0.0  0.0      0     0 ?        S    10:00   0:00 [kthreadd]\n")
		b.WriteString("root         450  0.0  0.1  28940  6240 ?        Ss   10:00   0:00 /lib/systemd/systemd-journald\n")
		b.WriteString("root         520  0.0  0.1  15820  7420 ?        Ss   10:00   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\n")
		fmt.Fprintf(&b, "root         648  0.0  0.2  18900  9100 ?        Ss   10:15   0:00 sshd: %s [priv]\n", u)
		fmt.Fprintf(&b, "%-8s     650  0.0  0.1  14200  5800 pts/0    Ss   10:15   0:00 -bash\n", u)
		fmt.Fprintf(&b, "%-8s     712  0.0  0.0  10400  3200 pts/0    R+   10:20   0:00 ps %s\n", u, flags)
		return b.String(), 0
	case strings.Contains(flags, "ef") || strings.Contains(flags, "-e"):
		var b strings.Builder
		b.WriteString("UID          PID    PPID  C STIME TTY          TIME CMD\n")
		b.WriteString("root           1       0  0 10:00 ?        00:00:02 /sbin/init\n")
		b.WriteString("root           2       0  0 10:00 ?        00:00:00 [kthreadd]\n")
		b.WriteString("root         520       1  0 10:00 ?        00:00:00 /usr/sbin/sshd -D\n")
		fmt.Fprintf(&b, "%-8s     650     648  0 10:15 pts/0    00:00:00 -bash\n", u)
		fmt.Fprintf(&b, "%-8s     712     650  0 10:20 pts/0    00:00:00 ps %s\n", u, flags)
		return b.String(), 0
	default:
		var b strings.Builder
		b.WriteString("    PID TTY          TIME CMD\n")
		b.WriteString("    650 pts/0    00:00:00 bash\n")
		b.WriteString("    712 pts/0    00:00:00 ps\n")
		return b.String(), 0
	}
}

func cmdTop(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	u := sh.User.Name
	var b strings.Builder
	b.WriteString("top - " + clockNow() + " up 14 days,  2:30,  1 user,  load average: 0.05, 0.03, 0.00\n")
	b.WriteString("Tasks: 102 total,   1 running, 101 sleeping,   0 stopped,   0 zombie\n")
	b.WriteString("%Cpu(s):  0.2 us,  0.1 sy,  0.0 ni, 99.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n")
	b.WriteString("MiB Mem :   7942.5 total,   4120.4 free,   1820.8 used,   2001.3 buff/cache\n")
	b.WriteString("MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5820.5 avail Mem \n\n")
	b.WriteString("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
	b.WriteString("      1 root      20   0  168420  12480   8420 S   0.0   0.2   0:02.15 systemd\n")
	b.WriteString("    520 root      20   0   15820   7420   6120 S   0.0   0.1   0:00.82 sshd\n")
	fmt.Fprintf(&b, "    650 %-8s  20   0   14200   5800   4200 S   0.0   0.1   0:00.12 bash\n", u)
	fmt.Fprintf(&b, "    715 %-8s  20   0   21400   4100   3200 R   0.0   0.1   0:00.01 top\n", u)
	return b.String(), 0
}

func cmdW(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	b.WriteString(" " + clockNow() + " up 14 days,  2:30,  1 user,  load average: 0.05, 0.03, 0.00\n")
	b.WriteString("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
	fmt.Fprintf(&b, "%-8s pts/0    10.0.0.1         12:30    0.00s  0.02s  0.00s w\n", sh.User.Name)
	return b.String(), 0
}

func cmdUptime(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return " " + clockNow() + " up 14 days,  2:30,  1 user,  load average: 0.05, 0.03, 0.00\n", 0
}

func cmdDate(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return time.Now().UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n", 0
}

func cmdDf(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	human := false
	for _, a := range args {
		if strings.Contains(a, "h") || strings.Contains(a, "H") {
			human = true
		}
	}
	if human {
		return "Filesystem      Size  Used Avail Use% Mounted on\n" +
			"udev            3.9G     0  3.9G   0% /dev\n" +
			"tmpfs           790M  1.3M  789M   1% /run\n" +
			"/dev/sda1        39G  6.6G   31G  18% /\n" +
			"tmpfs           3.9G     0  3.9G   0% /dev/shm\n" +
			"tmpfs           5.0M     0  5.0M   0% /run/lock\n", 0
	}
	return "Filesystem     1K-blocks    Used Available Use% Mounted on\n" +
		"udev             4012428       0   4012428   0% /dev\n" +
		"tmpfs             808244    1240    807004   1% /run\n" +
		"/dev/sda1       40629440 6842100  31698240  18% /\n" +
		"tmpfs            4041216       0   4041216   0% /dev/shm\n" +
		"tmpfs               5120       0      5120   0% /run/lock\n", 0
}

func cmdFree(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	flags := strings.Join(args, "")
	switch {
	case strings.Contains(flags, "h"):
		return "               total        used        free      shared  buff/cache   available\n" +
			"Mem:           7.8Gi       1.8Gi       4.0Gi       1.0Mi       2.0Gi       5.7Gi\n" +
			"Swap:          2.0Gi          0B       2.0Gi\n", 0
	case strings.Contains(flags, "m"):
		return "               total        used        free      shared  buff/cache   available\n" +
			"Mem:            7942        1820        4120           1        2001        5820\n" +
			"Swap:           2048           0        2048\n", 0
	default:
		return "               total        used        free      shared  buff/cache   available\n" +
			"Mem:         8133120     1863680     4219392        1024     2050048     5960192\n" +
			"Swap:        2097148           0     2097148\n", 0
	}
}

func cmdEnv(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	envVars := []struct {
		k, v string
	}{
		{"SHELL", "/bin/bash"},
		{"PWD", sh.Cwd},
		{"LOGNAME", sh.User.Name},
		{"HOME", sh.User.Home},
		{"LANG", "en_US.UTF-8"},
		{"SSH_CONNECTION", fmt.Sprintf("10.0.0.1 54321 %s 22", sh.P.InternalIP)},
		{"TERM", "xterm-256color"},
		{"USER", sh.User.Name},
		{"SHLVL", "1"},
		{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		{"HOSTNAME", sh.P.Hostname},
		{"_", "/usr/bin/env"},
	}

	if len(args) > 0 && !strings.Contains(args[0], "=") {
		key := args[0]
		for _, e := range envVars {
			if e.k == key {
				return e.v + "\n", 0
			}
		}
		return "", 1
	}

	var b strings.Builder
	for _, e := range envVars {
		fmt.Fprintf(&b, "%s=%s\n", e.k, e.v)
	}
	return b.String(), 0
}

func cmdNetstat(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	b.WriteString("Active Internet connections (servers and established)\n")
	b.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    \n")
	b.WriteString("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      520/sshd: /usr/sbin \n")
	b.WriteString("tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   \n")
	fmt.Fprintf(&b, "tcp        0      0 %s:22          10.0.0.1:54321          ESTABLISHED 648/sshd: %s\n", sh.P.InternalIP, sh.User.Name)
	b.WriteString("tcp6       0      0 :::22                   :::*                    LISTEN      520/sshd: /usr/sbin \n")
	return b.String(), 0
}

func cmdSS(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	b.WriteString("State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process\n")
	b.WriteString("LISTEN   0        128              0.0.0.0:22             0.0.0.0:*      users:((\"sshd\",pid=520,fd=3))\n")
	b.WriteString("LISTEN   0        128            127.0.0.1:5432           0.0.0.0:*     \n")
	fmt.Fprintf(&b, "ESTAB    0        0        %s:22          10.0.0.1:54321  users:((\"sshd\",pid=648,fd=4))\n", sh.P.InternalIP)
	b.WriteString("LISTEN   0        128                 [::]:22                [::]:*      users:((\"sshd\",pid=520,fd=4))\n")
	return b.String(), 0
}

func cmdIP(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	flags := strings.Join(args, " ")
	if strings.Contains(flags, "r") { // ip route
		return fmt.Sprintf("default via 10.0.0.1 dev eth0 proto dhcp src %s metric 100\n"+
			"10.0.0.0/24 dev eth0 proto kernel scope link src %s metric 100\n", sh.P.InternalIP, sh.P.InternalIP), 0
	}
	var b strings.Builder
	b.WriteString("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n")
	b.WriteString("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
	b.WriteString("    inet 127.0.0.1/8 scope host lo\n")
	b.WriteString("       valid_lft forever preferred_lft forever\n")
	b.WriteString("    inet6 ::1/128 scope host \n")
	b.WriteString("       valid_lft forever preferred_lft forever\n")
	b.WriteString("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n")
	b.WriteString("    link/ether 02:42:0a:00:00:02 brd ff:ff:ff:ff:ff:ff\n")
	fmt.Fprintf(&b, "    inet %s/24 brd 10.0.0.255 scope global eth0\n", sh.P.InternalIP)
	b.WriteString("       valid_lft forever preferred_lft forever\n")
	return b.String(), 0
}

func cmdIfconfig(sh *Shell, _ []string, _ string, _ *Result) (string, int) {
	var b strings.Builder
	fmt.Fprintf(&b, "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"+
		"        inet %s  netmask 255.255.255.0  broadcast 10.0.0.255\n"+
		"        ether 02:42:0a:00:00:02  txqueuelen 1000  (Ethernet)\n"+
		"        RX packets 1420  bytes 128420 (128.4 KB)\n"+
		"        TX packets 1120  bytes 194120 (194.1 KB)\n\n"+
		"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"+
		"        inet 127.0.0.1  netmask 255.0.0.0\n"+
		"        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"+
		"        loop  txqueuelen 1000  (Local Loopback)\n"+
		"        RX packets 24  bytes 1840 (1.8 KB)\n"+
		"        TX packets 24  bytes 1840 (1.8 KB)\n", sh.P.InternalIP)
	return b.String(), 0
}

func cmdWhich(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) == 0 {
		return "", 1
	}
	exit := 0
	var b strings.Builder
	for _, a := range args {
		if _, ok := commands[a]; ok {
			fmt.Fprintf(&b, "/usr/bin/%s\n", a)
		} else {
			exit = 1
		}
	}
	return b.String(), exit
}

// ---------- Files over fakefs ----------

func cmdFind(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	var roots []string
	namePat := ""
	inamePat := ""
	typeFilter := "" // "f" or "d"

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-name" && i+1 < len(args):
			namePat = args[i+1]
			i++
		case a == "-iname" && i+1 < len(args):
			inamePat = args[i+1]
			i++
		case a == "-type" && i+1 < len(args):
			typeFilter = args[i+1]
			i++
		case !strings.HasPrefix(a, "-"):
			roots = append(roots, a)
		}
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}

	matchNode := func(name string, isDir bool) bool {
		if typeFilter == "f" && isDir {
			return false
		}
		if typeFilter == "d" && !isDir {
			return false
		}
		if namePat != "" {
			m, _ := path.Match(namePat, name)
			if !m && namePat != name {
				return false
			}
		}
		if inamePat != "" {
			m, _ := path.Match(strings.ToLower(inamePat), strings.ToLower(name))
			if !m && strings.ToLower(inamePat) != strings.ToLower(name) {
				return false
			}
		}
		return true
	}

	var out strings.Builder
	exit := 0

	var walk func(absDir, dispDir string)
	walk = func(absDir, dispDir string) {
		children := sh.FS.List(absDir)
		for _, c := range children {
			cAbs := path.Join(absDir, c.Name)
			cDisp := path.Join(dispDir, c.Name)
			if matchNode(c.Name, c.Dir) {
				out.WriteString(cDisp + "\n")
			}
			if c.Dir {
				if len(c.Mode) == 10 && (c.Mode[7] == 45 || c.Mode[9] == 45) && sh.User.UID != 0 && c.Owner != sh.User.Name {
					out.WriteString("find: '" + cDisp + "': Permission denied\n")
					continue
				}
				walk(cAbs, cDisp)
			}
		}
	}

	for _, r := range roots {
		absPath := sh.abs(r)
		node := sh.FS.Get(absPath)
		if node == nil {
			fmt.Fprintf(&out, "find: %q: No such file or directory\n", r)
			exit = 1
			continue
		}
		if matchNode(path.Base(absPath), node.Dir) {
			out.WriteString(r + "\n")
		}
		if node.Dir {
			walk(absPath, r)
		}
	}
	return out.String(), exit
}

func cmdGrep(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	recursive := false
	ignoreCase := false
	lineNum := false
	filesOnly := false
	invert := false
	pattern := ""
	var fileArgs []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-r" || a == "-R":
			recursive = true
		case a == "-i":
			ignoreCase = true
		case a == "-n":
			lineNum = true
		case a == "-l":
			filesOnly = true
		case a == "-v":
			invert = true
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for _, ch := range a[1:] {
				switch ch {
				case 'r', 'R':
					recursive = true
				case 'i':
					ignoreCase = true
				case 'n':
					lineNum = true
				case 'l':
					filesOnly = true
				case 'v':
					invert = true
				}
			}
		default:
			if pattern == "" {
				pattern = a
			} else {
				fileArgs = append(fileArgs, a)
			}
		}
	}

	if pattern == "" {
		return "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
	}

	matchesLine := func(line string) bool {
		l := line
		p := pattern
		if ignoreCase {
			l = strings.ToLower(l)
			p = strings.ToLower(p)
		}
		m := strings.Contains(l, p)
		if invert {
			return !m
		}
		return m
	}

	// Stdin case
	if len(fileArgs) == 0 && !recursive {
		var out strings.Builder
		lines := strings.Split(stdin, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		matchedAny := false
		for idx, l := range lines {
			if matchesLine(l) {
				matchedAny = true
				if filesOnly {
					return "(standard input)\n", 0
				}
				if lineNum {
					fmt.Fprintf(&out, "%d:%s\n", idx+1, l)
				} else {
					out.WriteString(l + "\n")
				}
			}
		}
		if matchedAny {
			return out.String(), 0
		}
		return "", 1
	}

	// File / recursive case
	if len(fileArgs) == 0 && recursive {
		fileArgs = []string{"."}
	}

	type fileItem struct {
		absPath  string
		dispPath string
	}
	var files []fileItem

	var collectFiles func(absDir, dispDir string)
	collectFiles = func(absDir, dispDir string) {
		for _, c := range sh.FS.List(absDir) {
			childAbs := path.Join(absDir, c.Name)
			childDisp := path.Join(dispDir, c.Name)
			if c.Dir {
				collectFiles(childAbs, childDisp)
			} else {
				files = append(files, fileItem{absPath: childAbs, dispPath: childDisp})
			}
		}
	}

	for _, fa := range fileArgs {
		ap := sh.abs(fa)
		n := sh.FS.Get(ap)
		if n == nil {
			continue
		}
		if n.Dir {
			if recursive {
				collectFiles(ap, fa)
			}
		} else {
			files = append(files, fileItem{absPath: ap, dispPath: fa})
		}
	}

	multiple := len(files) > 1 || recursive
	var out strings.Builder
	matchedTotal := false

	for _, fi := range files {
		n := sh.FS.Get(fi.absPath)
		if n == nil || n.Dir {
			continue
		}
		// Check permission
		if len(n.Mode) == 10 && n.Mode[7] == 45 && sh.User.UID != 0 && n.Owner != sh.User.Name {
			continue
		}

		lines := strings.Split(n.Content, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		fileMatched := false
		var fileOut strings.Builder
		for idx, l := range lines {
			if matchesLine(l) {
				fileMatched = true
				matchedTotal = true
				if filesOnly {
					out.WriteString(fi.dispPath + "\n")
					break
				}
				if multiple {
					fileOut.WriteString(fi.dispPath + ":")
				}
				if lineNum {
					fmt.Fprintf(&fileOut, "%d:", idx+1)
				}
				fileOut.WriteString(l + "\n")
			}
		}
		if fileMatched {
			res.Reads = append(res.Reads, FileRead{
				Path:        fi.absPath,
				HoneyfileID: n.HoneyfileID,
				MazeNode:    n.MazeNode,
				Bytes:       len(n.Content),
			})
			if !filesOnly {
				out.WriteString(fileOut.String())
			}
		}
	}

	if matchedTotal {
		return out.String(), 0
	}
	return "", 1
}

func cmdHead(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	nLines := 10
	var fileArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil && v >= 0 {
				nLines = v
			}
			i++
		} else if strings.HasPrefix(a, "-n") {
			if v, err := strconv.Atoi(a[2:]); err == nil && v >= 0 {
				nLines = v
			}
		} else if strings.HasPrefix(a, "-") && len(a) > 1 {
			if v, err := strconv.Atoi(a[1:]); err == nil && v >= 0 {
				nLines = v
			}
		} else {
			fileArgs = append(fileArgs, a)
		}
	}

	if len(fileArgs) == 0 {
		lines := strings.Split(stdin, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if nLines > len(lines) {
			nLines = len(lines)
		}
		var b strings.Builder
		for i := 0; i < nLines; i++ {
			b.WriteString(lines[i] + "\n")
		}
		return b.String(), 0
	}

	var out strings.Builder
	exit := 0
	multiple := len(fileArgs) > 1

	for _, fa := range fileArgs {
		ap := sh.abs(fa)
		n := sh.FS.Get(ap)
		if n == nil {
			fmt.Fprintf(&out, "head: cannot open %q for reading: No such file or directory\n", fa)
			exit = 1
			continue
		}
		if n.Dir {
			fmt.Fprintf(&out, "head: error reading %q: Is a directory\n", fa)
			exit = 1
			continue
		}
		if len(n.Mode) == 10 && n.Mode[7] == 45 && sh.User.UID != 0 && n.Owner != sh.User.Name {
			fmt.Fprintf(&out, "head: cannot open %q for reading: Permission denied\n", fa)
			exit = 1
			continue
		}

		if multiple {
			fmt.Fprintf(&out, "==> %s <==\n", fa)
		}
		lines := strings.Split(n.Content, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		take := nLines
		if take > len(lines) {
			take = len(lines)
		}
		for i := 0; i < take; i++ {
			out.WriteString(lines[i] + "\n")
		}
		res.Reads = append(res.Reads, FileRead{
			Path:        ap,
			HoneyfileID: n.HoneyfileID,
			MazeNode:    n.MazeNode,
			Bytes:       len(n.Content),
		})
	}
	return out.String(), exit
}

func cmdTail(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	nLines := 10
	var fileArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil && v >= 0 {
				nLines = v
			}
			i++
		} else if strings.HasPrefix(a, "-n") {
			if v, err := strconv.Atoi(a[2:]); err == nil && v >= 0 {
				nLines = v
			}
		} else if strings.HasPrefix(a, "-") && len(a) > 1 {
			if v, err := strconv.Atoi(a[1:]); err == nil && v >= 0 {
				nLines = v
			}
		} else {
			fileArgs = append(fileArgs, a)
		}
	}

	if len(fileArgs) == 0 {
		lines := strings.Split(stdin, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		start := len(lines) - nLines
		if start < 0 {
			start = 0
		}
		var b strings.Builder
		for i := start; i < len(lines); i++ {
			b.WriteString(lines[i] + "\n")
		}
		return b.String(), 0
	}

	var out strings.Builder
	exit := 0
	multiple := len(fileArgs) > 1

	for _, fa := range fileArgs {
		ap := sh.abs(fa)
		n := sh.FS.Get(ap)
		if n == nil {
			fmt.Fprintf(&out, "tail: cannot open %q for reading: No such file or directory\n", fa)
			exit = 1
			continue
		}
		if n.Dir {
			fmt.Fprintf(&out, "tail: error reading %q: Is a directory\n", fa)
			exit = 1
			continue
		}
		if len(n.Mode) == 10 && n.Mode[7] == 45 && sh.User.UID != 0 && n.Owner != sh.User.Name {
			fmt.Fprintf(&out, "tail: cannot open %q for reading: Permission denied\n", fa)
			exit = 1
			continue
		}

		if multiple {
			fmt.Fprintf(&out, "==> %s <==\n", fa)
		}
		lines := strings.Split(n.Content, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		start := len(lines) - nLines
		if start < 0 {
			start = 0
		}
		for i := start; i < len(lines); i++ {
			out.WriteString(lines[i] + "\n")
		}
		res.Reads = append(res.Reads, FileRead{
			Path:        ap,
			HoneyfileID: n.HoneyfileID,
			MazeNode:    n.MazeNode,
			Bytes:       len(n.Content),
		})
	}
	return out.String(), exit
}

func cmdWc(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	lineOnly := false
	var fileArgs []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				lineOnly = true
			}
		} else {
			fileArgs = append(fileArgs, a)
		}
	}

	countLines := func(s string) int {
		c := strings.Count(s, "\n")
		return c
	}

	if len(fileArgs) == 0 {
		lc := countLines(stdin)
		return fmt.Sprintf("%d\n", lc), 0
	}

	var out strings.Builder
	exit := 0
	totalLines := 0

	for _, fa := range fileArgs {
		ap := sh.abs(fa)
		n := sh.FS.Get(ap)
		if n == nil {
			fmt.Fprintf(&out, "wc: %s: No such file or directory\n", fa)
			exit = 1
			continue
		}
		if n.Dir {
			fmt.Fprintf(&out, "wc: %s: Is a directory\n", fa)
			exit = 1
			continue
		}
		if len(n.Mode) == 10 && n.Mode[7] == 45 && sh.User.UID != 0 && n.Owner != sh.User.Name {
			fmt.Fprintf(&out, "wc: %s: Permission denied\n", fa)
			exit = 1
			continue
		}

		lc := countLines(n.Content)
		totalLines += lc
		if lineOnly {
			fmt.Fprintf(&out, "%d %s\n", lc, fa)
		} else {
			words := len(strings.Fields(n.Content))
			fmt.Fprintf(&out, "%d %d %d %s\n", lc, words, len(n.Content), fa)
		}
		res.Reads = append(res.Reads, FileRead{
			Path:        ap,
			HoneyfileID: n.HoneyfileID,
			MazeNode:    n.MazeNode,
			Bytes:       len(n.Content),
		})
	}

	if len(fileArgs) > 1 {
		if lineOnly {
			fmt.Fprintf(&out, "%d total\n", totalLines)
		} else {
			fmt.Fprintf(&out, "%d total\n", totalLines)
		}
	}
	return out.String(), exit
}

// ---------- Overlay Changes ----------

func cmdTouch(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	exit := 0
	var out strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := sh.abs(a)
		if !sh.FS.Write(p, "", sh.User.Name, true) {
			fmt.Fprintf(&out, "touch: cannot touch %q: No such file or directory\n", a)
			exit = 1
		}
	}
	return out.String(), exit
}

func cmdMkdir(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	parents := false
	var targets []string
	for _, a := range args {
		if a == "-p" || a == "--parents" {
			parents = true
		} else if !strings.HasPrefix(a, "-") {
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		return "mkdir: missing operand\n", 1
	}

	var out strings.Builder
	exit := 0

	for _, t := range targets {
		ap := sh.abs(t)
		if parents {
			parts := strings.Split(ap, "/")
			cur := ""
			for _, part := range parts {
				if part == "" {
					continue
				}
				cur += "/" + part
				if node := sh.FS.Get(cur); node == nil {
					sh.FS.Mkdir(cur, sh.User.Name)
				}
			}
		} else {
			if node := sh.FS.Get(ap); node != nil {
				fmt.Fprintf(&out, "mkdir: cannot create directory %q: File exists\n", t)
				exit = 1
				continue
			}
			if !sh.FS.Mkdir(ap, sh.User.Name) {
				fmt.Fprintf(&out, "mkdir: cannot create directory %q: No such file or directory\n", t)
				exit = 1
			}
		}
	}
	return out.String(), exit
}

func cmdRm(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	recursive := false
	force := false
	var targets []string

	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "r") || strings.Contains(a, "R") {
				recursive = true
			}
			if strings.Contains(a, "f") {
				force = true
			}
		} else {
			targets = append(targets, a)
		}
	}

	if len(targets) == 0 {
		if force {
			return "", 0
		}
		return "rm: missing operand\n", 1
	}

	var out strings.Builder
	exit := 0

	for _, t := range targets {
		ap := sh.abs(t)
		n := sh.FS.Get(ap)
		if n == nil {
			if !force {
				fmt.Fprintf(&out, "rm: cannot remove %q: No such file or directory\n", t)
				exit = 1
			}
			continue
		}
		if n.Dir && !recursive {
			fmt.Fprintf(&out, "rm: cannot remove %q: Is a directory\n", t)
			exit = 1
			continue
		}
		sh.FS.Remove(ap)
	}
	return out.String(), exit
}

func cmdCp(sh *Shell, args []string, _ string, res *Result) (string, int) {
	recursive := false
	var paths []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "r") || strings.Contains(a, "R") {
				recursive = true
			}
		} else {
			paths = append(paths, a)
		}
	}
	if len(paths) < 2 {
		return "cp: missing destination file operand\n", 1
	}

	src := sh.abs(paths[0])
	dst := sh.abs(paths[1])

	srcNode := sh.FS.Get(src)
	if srcNode == nil {
		return fmt.Sprintf("cp: cannot stat %q: No such file or directory\n", paths[0]), 1
	}

	if srcNode.Dir {
		if !recursive {
			return fmt.Sprintf("cp: -r not specified; omitting directory %q\n", paths[0]), 1
		}
		sh.FS.Mkdir(dst, sh.User.Name)
		var copyTree func(sAbs, dAbs string)
		copyTree = func(sAbs, dAbs string) {
			for _, child := range sh.FS.List(sAbs) {
				childSrc := path.Join(sAbs, child.Name)
				childDst := path.Join(dAbs, child.Name)
				if child.Dir {
					sh.FS.Mkdir(childDst, sh.User.Name)
					copyTree(childSrc, childDst)
				} else {
					sh.FS.Write(childDst, child.Content, sh.User.Name, false)
				}
			}
		}
		copyTree(src, dst)
		return "", 0
	}

	res.Reads = append(res.Reads, FileRead{
		Path:        src,
		HoneyfileID: srcNode.HoneyfileID,
		MazeNode:    srcNode.MazeNode,
		Bytes:       len(srcNode.Content),
	})

	dstNode := sh.FS.Get(dst)
	if dstNode != nil && dstNode.Dir {
		dst = path.Join(dst, path.Base(src))
	}
	if !sh.FS.Write(dst, srcNode.Content, sh.User.Name, false) {
		return fmt.Sprintf("cp: cannot create regular file %q: No such file or directory\n", paths[1]), 1
	}
	return "", 0
}

func cmdMv(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	var paths []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			paths = append(paths, a)
		}
	}
	if len(paths) < 2 {
		return "mv: missing destination file operand\n", 1
	}

	src := sh.abs(paths[0])
	dst := sh.abs(paths[1])

	srcNode := sh.FS.Get(src)
	if srcNode == nil {
		return fmt.Sprintf("mv: cannot stat %q: No such file or directory\n", paths[0]), 1
	}

	dstNode := sh.FS.Get(dst)
	if dstNode != nil && dstNode.Dir {
		dst = path.Join(dst, path.Base(src))
	}

	if srcNode.Dir {
		sh.FS.Mkdir(dst, sh.User.Name)
		var moveTree func(sAbs, dAbs string)
		moveTree = func(sAbs, dAbs string) {
			for _, child := range sh.FS.List(sAbs) {
				childSrc := path.Join(sAbs, child.Name)
				childDst := path.Join(dAbs, child.Name)
				if child.Dir {
					sh.FS.Mkdir(childDst, sh.User.Name)
					moveTree(childSrc, childDst)
				} else {
					sh.FS.Write(childDst, child.Content, sh.User.Name, false)
				}
			}
		}
		moveTree(src, dst)
		sh.FS.Remove(src)
		return "", 0
	}

	sh.FS.Write(dst, srcNode.Content, sh.User.Name, false)
	sh.FS.Remove(src)
	return "", 0
}

func cmdChmod(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) < 2 {
		return "chmod: missing operand\n", 1
	}
	modeArg := args[0]
	exit := 0
	var out strings.Builder

	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		ap := sh.abs(a)
		n := sh.FS.Get(ap)
		if n == nil {
			fmt.Fprintf(&out, "chmod: cannot access %q: No such file or directory\n", a)
			exit = 1
			continue
		}
		newMode := parseModeString(n.Mode, modeArg)
		sh.FS.Chmod(ap, newMode)
	}
	return out.String(), exit
}

func parseModeString(origMode, arg string) string {
	dirPrefix := "-"
	if len(origMode) > 0 && origMode[0] == 100 { // 'd'
		dirPrefix = "d"
	}
	numStr := strings.TrimPrefix(arg, "0")
	if len(numStr) == 3 {
		toRwx := func(c byte) string {
			switch c {
			case 55: // '7'
				return "rwx"
			case 54: // '6'
				return "rw-"
			case 53: // '5'
				return "r-x"
			case 52: // '4'
				return "r--"
			case 51: // '3'
				return "-wx"
			case 50: // '2'
				return "-w-"
			case 49: // '1'
				return "--x"
			default:
				return "---"
			}
		}
		return dirPrefix + toRwx(numStr[0]) + toRwx(numStr[1]) + toRwx(numStr[2])
	}
	if strings.Contains(arg, "+x") {
		return dirPrefix + "rwxr-xr-x"
	}
	return origMode
}

func cmdChown(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) < 2 {
		return "chown: missing operand\n", 1
	}
	ownerArg := args[0]
	owner := strings.Split(ownerArg, ":")[0]
	owner = strings.Split(owner, ".")[0]

	exit := 0
	var out strings.Builder
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		ap := sh.abs(a)
		if n := sh.FS.Get(ap); n == nil {
			fmt.Fprintf(&out, "chown: cannot access %q: No such file or directory\n", a)
			exit = 1
			continue
		}
		sh.FS.Chown(ap, owner)
	}
	return out.String(), exit
}

// ---------- Network Simulators (wget / curl) ----------

func cmdWget(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	url := ""
	outputFile := ""

	for i := 0; i < len(args); i++ {
		a := args[i]
		if (a == "-O" || a == "--output-document") && i+1 < len(args) {
			outputFile = args[i+1]
			i++
		} else if !strings.HasPrefix(a, "-") && url == "" {
			url = a
		}
	}

	if url == "" {
		return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n", 1
	}

	if outputFile == "" {
		outputFile = path.Base(url)
		if outputFile == "" || outputFile == "." || outputFile == "/" {
			outputFile = "index.html"
		}
	}

	sh.FS.Write(sh.abs(outputFile), "", sh.User.Name, false)

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	host := url
	if parts := strings.Split(url, "/"); len(parts) > 2 {
		host = parts[2]
	}
	host = strings.Split(host, ":")[0]

	var b strings.Builder
	fmt.Fprintf(&b, "--%s--  %s\n", now, url)
	if isIPv4Literal(host) { // wget never "resolves" an address it was given
		fmt.Fprintf(&b, "Connecting to %s:80... connected.\n", host)
	} else {
		fmt.Fprintf(&b, "Resolving %s (%s)... 10.0.0.1\n", host, host)
		fmt.Fprintf(&b, "Connecting to %s (%s)|10.0.0.1|:80... connected.\n", host, host)
	}
	b.WriteString("HTTP request sent, awaiting response... 200 OK\n")
	b.WriteString("Length: 0 [application/octet-stream]\n")
	fmt.Fprintf(&b, "Saving to: %q\n\n", outputFile)
	fmt.Fprintf(&b, "%-19s 100%%[===================>]       0  --.-KB/s    in 0s      \n\n", outputFile)
	fmt.Fprintf(&b, "%s (0 B/s) - %q saved [0/0]\n", now, outputFile)
	return b.String(), 0
}

func cmdCurl(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	url := ""
	outputFile := ""

	for i := 0; i < len(args); i++ {
		a := args[i]
		if (a == "-o" || a == "--output") && i+1 < len(args) {
			outputFile = args[i+1]
			i++
		} else if a == "-O" || a == "--remote-name" {
			// will resolve
		} else if !strings.HasPrefix(a, "-") && url == "" {
			url = a
		}
	}

	for _, a := range args {
		if a == "-O" || a == "--remote-name" {
			if url != "" {
				outputFile = path.Base(url)
			}
		}
	}

	if outputFile != "" && outputFile != "/dev/null" {
		sh.FS.Write(sh.abs(outputFile), "", sh.User.Name, false)
	}

	return "", 0
}

// ---------- Auth & Privilege (sudo / su) ----------

func cmdSudo(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	if sh.User.UID == 0 {
		if len(args) == 0 {
			return "", 0
		}
		return sh.exec(args, stdin, res)
	}
	if !sh.Interactive {
		return "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper\n", 1
	}
	sh.pending = &pendingAuth{kind: "sudo", tries: 3}
	res.SecretPrompt = sh.sudoPrompt()
	return "", 0
}

func cmdSu(sh *Shell, args []string, _ string, res *Result) (string, int) {
	if !sh.Interactive {
		return "su: must be run from a terminal\n", 1
	}
	sh.pending = &pendingAuth{kind: "su", tries: 1}
	res.SecretPrompt = "Password: "
	return "", 0
}

// ---------- Services & Tools ----------

func cmdMysql(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)\n", 1
}

func cmdPsql(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "psql: error: connection to server on socket \"/var/run/postgresql/.s.PGSQL.5432\" failed: No such file or directory\n", 2
}

func cmdKubectl(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	hasKube := sh.FS.Get("/opt/deploy/kubeconfig") != nil || sh.FS.Get(sh.User.Home+"/.kube/config") != nil
	cmdStr := strings.Join(args, " ")
	if hasKube {
		if strings.Contains(cmdStr, "get") && strings.Contains(cmdStr, "pod") {
			return "NAME                           READY   STATUS    RESTARTS   AGE\n" +
				"frontend-6b47c9459b-v8k2p     1/1     Running   0          4d12h\n" +
				"backend-api-5d8f7b764c-z9m4q   1/1     Running   0          4d12h\n" +
				"redis-master-0                 1/1     Running   0          12d\n", 0
		}
		if strings.Contains(cmdStr, "get") && strings.Contains(cmdStr, "secret") {
			return "NAME                  TYPE                                  DATA   AGE\n" +
				"default-token-4kx9p   kubernetes.io/service-account-token   3      12d\n" +
				"app-secret            Opaque                                2      4d12h\n", 0
		}
	}
	return "The connection to the server localhost:8080 was refused - did you specify the right host or port?\n", 1
}

func cmdDocker(_ *Shell, _ []string, _ string, _ *Result) (string, int) {
	return "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n", 1
}

func cmdCrontab(sh *Shell, args []string, _ string, _ *Result) (string, int) {
	for _, a := range args {
		if strings.Contains(a, "l") {
			return fmt.Sprintf("no crontab for %s\n", sh.User.Name), 1
		}
	}
	return "crontab: usage error: file name must be specified for install\n", 1
}

func cmdExport(sh *Shell, args []string, stdin string, res *Result) (string, int) {
	if len(args) == 0 {
		return cmdEnv(sh, args, stdin, res)
	}
	return "", 0
}

func cmdAlias(_ *Shell, args []string, _ string, _ *Result) (string, int) {
	if len(args) == 0 {
		return "alias ll='ls -alF'\n", 0
	}
	return "", 0
}

// clockNow is the wall-clock time shown by uptime / w / top (a fixed time is an easy honeypot tell).
func clockNow() string { return time.Now().UTC().Format("15:04:05") }

// isIPv4Literal reports whether h is a dotted-quad address.
func isIPv4Literal(h string) bool {
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}
