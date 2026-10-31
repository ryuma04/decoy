package web

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"

	"github.com/ryuma04/decoy/backend/internal/persona"
)

var hostRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`)

type PrecheckResult struct {
	IsSuspicious bool
	Separator    string
	Payload      string
}

// CheckInput performs the cheap pre-check from docs/06-decoys.md §2.
// Looks for separators: ;, &&, ||, |, `, $(, %0a, \n; SQL ' OR, UNION SELECT, --; ../; <script.
func CheckInput(rawVal string) PrecheckResult {
	if rawVal == "" {
		return PrecheckResult{IsSuspicious: false}
	}

	decoded, err := url.QueryUnescape(rawVal)
	if err != nil {
		decoded = rawVal
	}

	// 1. If it strictly matches the valid hostname/IP pattern, it's clean
	if hostRegex.MatchString(rawVal) && !strings.Contains(rawVal, "..") {
		return PrecheckResult{IsSuspicious: false}
	}

	// 2. Ordered separators to test (longer first to prevent partial matches like & before &&)
	separators := []string{
		"&&",
		"||",
		";",
		"|",
		"`",
		"$(",
		"%0a",
		"%0A",
		"\n",
		"' OR",
		"' or",
		"UNION SELECT",
		"union select",
		"--",
		"../",
		"<script",
	}

	checkTargets := []struct {
		str       string
		isDecoded bool
	}{
		{str: rawVal, isDecoded: false},
		{str: decoded, isDecoded: true},
	}

	for _, target := range checkTargets {
		for _, sep := range separators {
			idx := strings.Index(target.str, sep)
			if idx != -1 {
				payload := strings.TrimSpace(target.str[idx+len(sep):])
				// Clean trailing backticks or quotes if present
				payload = strings.Trim(payload, "`\"'")
				return PrecheckResult{
					IsSuspicious: true,
					Separator:    sep,
					Payload:      payload,
				}
			}
		}
	}

	// If it failed regex without an explicit separator, mark as suspicious with whole value as payload
	return PrecheckResult{
		IsSuspicious: true,
		Separator:    "",
		Payload:      strings.TrimSpace(decoded),
	}
}

// EmulateDiagnosticsOutput returns simulated command output or ping output.
func EmulateDiagnosticsOutput(host string, check PrecheckResult, p persona.Persona) string {
	if !check.IsSuspicious {
		// Realistic ping output
		fakeIP := p.InternalIP
		if fakeIP == "" {
			fakeIP = "10.0.4.12"
		}
		rtt1 := 12.0 + rand.Float64()*3.0
		rtt2 := 11.5 + rand.Float64()*3.0
		rtt3 := 12.2 + rand.Float64()*3.0
		avg := (rtt1 + rtt2 + rtt3) / 3.0
		return fmt.Sprintf(`PING %s (%s): 56 data bytes
64 bytes from %s: icmp_seq=0 ttl=64 time=%.1f ms
64 bytes from %s: icmp_seq=1 ttl=64 time=%.1f ms
64 bytes from %s: icmp_seq=2 ttl=64 time=%.1f ms

--- %s ping statistics ---
3 packets transmitted, 3 packets received, 0.0%% packet loss
round-trip min/avg/max = %.3f/%.3f/%.3f ms
`, host, fakeIP, fakeIP, rtt1, fakeIP, rtt2, fakeIP, rtt3, host, rtt2, avg, rtt3)
	}

	// Fake shell output for common payload targets
	cleanPayload := strings.ToLower(strings.TrimSpace(check.Payload))
	switch {
	case cleanPayload == "id" || strings.HasPrefix(cleanPayload, "id "):
		return "uid=1001(app) gid=1001(app) groups=1001(app),1002(deploy)\n"
	case cleanPayload == "whoami":
		return "app\n"
	case strings.Contains(cleanPayload, "etc/passwd"):
		return fmt.Sprintf(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash
app:x:1001:1001:Web App User:/home/app:/bin/sh
`)
	case strings.Contains(cleanPayload, "etc/shadow"):
		return "cat: /etc/shadow: Permission denied\n"
	case cleanPayload == "uname" || strings.HasPrefix(cleanPayload, "uname"):
		return fmt.Sprintf("Linux %s 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", p.Hostname)
	case cleanPayload == "pwd":
		return "/var/www/admin\n"
	case strings.HasPrefix(cleanPayload, "ls"):
		return "app.js\nconfig.json\npackage.json\npublic\nroutes\nviews\n"
	case strings.Contains(cleanPayload, "script"):
		return "Error: Invalid character sequence detected.\n"
	case strings.Contains(cleanPayload, "union") || strings.Contains(cleanPayload, "select") || strings.Contains(cleanPayload, "'"):
		return "Error: syntax error at or near \"'\": unexpected token in expression\n"
	case strings.Contains(cleanPayload, ".."):
		return "Error: path traversal detected: file not found or invalid path\n"
	default:
		cmdName := strings.Fields(cleanPayload)
		if len(cmdName) > 0 {
			return fmt.Sprintf("sh: 1: %s: not found\n", cmdName[0])
		}
		return "sh: 1: command execution finished with code 0\n"
	}
}

