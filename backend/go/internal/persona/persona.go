// Package persona generates the fake company every decoy presents (06), deterministic from PERSONA_SEED.
// cmd/seed writes it to seed/out/persona.json; decoys load that file and fall back to Generate(seed).
package persona

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"strings"
)

type User struct {
	Name     string `json:"name"`
	UID      int    `json:"uid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
	FullName string `json:"full_name"`
}

type Persona struct {
	Seed           string `json:"seed"`
	Company        string `json:"company"` // "Northwind Logistics"
	Domain         string `json:"domain"`  // "northwind-logistics.internal"
	HostPrefix     string `json:"host_prefix"`
	Hostname       string `json:"hostname"` // "nwl-app-01"
	Users          []User `json:"users"`
	RootPassword   string `json:"root_password"`   // weak, accepted by the SSH decoy
	DeployPassword string `json:"deploy_password"` // accepted by the SSH decoy
	Kernel         string `json:"kernel"`
	OS             string `json:"os"`
	InternalIP     string `json:"internal_ip"`
}

var (
	companies = []string{"Northwind", "Bluepeak", "Harborline", "Silverfern", "Redcliff", "Ironbridge", "Lakeshore", "Greenfield"}
	firsts    = []string{"anika", "rohan", "meera", "david", "sara", "imran", "lena", "vikram", "tara", "omar"}
	lasts     = []string{"shah", "fernandes", "iyer", "cohen", "kapoor", "mehta", "nair", "brooks", "das", "khan"}
	weak      = []string{"admin123", "Welcome1", "password1", "Spring2026!", "changeme", "P@ssw0rd"}
	seasons   = []string{"Summer", "Winter", "Monsoon", "Autumn"}
)

// Generate builds a persona from a seed string (same seed, same persona).
func Generate(seed string) Persona {
	h := fnv.New64a()
	h.Write([]byte(seed))
	r := rand.New(rand.NewPCG(h.Sum64(), 0x5eed))
	pick := func(xs []string) string { return xs[r.IntN(len(xs))] }

	name := pick(companies)
	prefix := strings.ToLower(name[:2]) + "l"
	first, last := pick(firsts), pick(lasts)
	p := Persona{
		Seed:       seed,
		Company:    name + " Logistics",
		Domain:     strings.ToLower(name) + "-logistics.internal",
		HostPrefix: prefix,
		Hostname:   prefix + "-app-01",
		Users: []User{
			{Name: "deploy", UID: 1001, Home: "/home/deploy", Shell: "/bin/bash", FullName: "Deploy User"},
			{Name: "jenkins", UID: 1002, Home: "/var/lib/jenkins", Shell: "/bin/bash", FullName: "Jenkins"},
			{Name: first + "." + last, UID: 1003, Home: "/home/" + first + "." + last, Shell: "/bin/bash",
				FullName: upperFirst(first) + " " + upperFirst(last)},
		},
		RootPassword:   pick(weak),
		DeployPassword: fmt.Sprintf("%s%s%d!", upperFirst(prefix), pick(seasons), 2020+r.IntN(7)),
		Kernel:         "5.15.0-" + fmt.Sprint(80+r.IntN(40)) + "-generic",
		OS:             "Ubuntu 22.04.4 LTS",
		InternalIP:     fmt.Sprintf("10.66.0.%d", 10+r.IntN(20)),
	}
	return p
}

// Load reads persona.json from dir; if it is missing, it generates one from seed.
func Load(path, seed string) Persona {
	b, err := os.ReadFile(path)
	if err == nil {
		var p Persona
		if json.Unmarshal(b, &p) == nil && p.Hostname != "" {
			return p
		}
	}
	if seed == "" {
		seed = "dsoc-default"
	}
	return Generate(seed)
}

// User returns the user with the given name.
func (p Persona) User(name string) (User, bool) {
	if name == "root" {
		return User{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash", FullName: "root"}, true
	}
	for _, u := range p.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
