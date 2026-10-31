package ssh

import (
	"fmt"
	"strings"

	"github.com/ryuma04/decoy/backend/internal/fakefs"
	"github.com/ryuma04/decoy/backend/internal/persona"
)

// Lure is a planted file from cmd/seed (honeytoken content); maze-gated when Hidden.
type Lure struct {
	Path        string `json:"path"`
	Content     string `json:"content"`
	HoneyfileID string `json:"honeyfile_id"`
	MazeNode    string `json:"maze_node"`
	Owner       string `json:"owner"`
	Mode        string `json:"mode"`
	Hidden      bool   `json:"hidden"`
}

// BaseTree builds the shared fake filesystem from the persona plus seeded lures.
func BaseTree(p persona.Persona, lures []Lure) map[string]*fakefs.Node {
	base := fakefs.NewBase()
	add := func(path, owner, mode, content string) {
		fakefs.Add(base, path, fakefs.Node{Owner: owner, Mode: mode, Content: content})
	}
	dir := func(path, owner string) { fakefs.Add(base, path, fakefs.Node{Dir: true, Owner: owner}) }

	for _, d := range []string{"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/opt", "/proc", "/root", "/srv",
		"/tmp", "/usr", "/usr/bin", "/usr/local", "/var", "/var/log", "/var/www", "/etc/app"} {
		dir(d, "root")
	}
	add("/etc/hostname", "root", "", p.Hostname+"\n")
	add("/etc/os-release", "root", "", fmt.Sprintf("PRETTY_NAME=%q\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n", p.OS))
	add("/etc/hosts", "root", "", fmt.Sprintf("127.0.0.1 localhost\n%s %s %s.%s\n", p.InternalIP, p.Hostname, p.Hostname, p.Domain))
	add("/etc/shadow", "root", "-rw-r-----", "root:$6$rounds=5000$fake$Tg0lJ1rI1yZ0n7FjzB1F2lK3zJ9xQ9m1aB2c3D4e5F6:19700:0:99999:7:::\n")

	var passwd strings.Builder
	passwd.WriteString("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n")
	for _, u := range p.Users {
		fmt.Fprintf(&passwd, "%s:x:%d:%d:%s:%s:%s\n", u.Name, u.UID, u.UID, u.FullName, u.Home, u.Shell)
		dir(u.Home, u.Name)
		add(u.Home+"/.bashrc", u.Name, "", "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll='ls -alF'\n")
		add(u.Home+"/.profile", u.Name, "", "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n")
	}
	add("/etc/passwd", "root", "", passwd.String())
	add("/home/deploy/notes.txt", "deploy", "", fmt.Sprintf("deploy checklist for %s\n- pull latest release\n- restart app service\n- check /var/log/app.log\n", p.Company))
	add("/var/log/app.log", "root", "", "2026-11-13T22:10:04Z INFO app started\n2026-11-13T22:10:05Z INFO connected to db\n")
	add("/root/.bashrc", "root", "-rw-------", "# root bashrc\n")

	for _, l := range lures {
		fakefs.Add(base, l.Path, fakefs.Node{Content: l.Content, HoneyfileID: l.HoneyfileID, MazeNode: l.MazeNode,
			Owner: l.Owner, Mode: l.Mode, Hidden: l.Hidden})
	}
	return base
}
