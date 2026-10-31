package db

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PGError is a Postgres error response (SQLSTATE code + message).
type PGError struct{ Code, Msg string }

// Result is what one statement returns. Kind classifies it for the SOC: recon | read | write | admin | session.
type Result struct {
	Columns []string
	Rows    [][]string
	Tag     string
	Kind    string
	Table   string
	Err     *PGError
}

var (
	reFrom     = regexp.MustCompile(`(?is)\bfrom\s+("?[\w.]+"?)`)
	reSelect   = regexp.MustCompile(`(?is)^\s*select\s+(.*?)\s+from\s`)
	reLimit    = regexp.MustCompile(`(?is)\blimit\s+(\d+)`)
	reWhereID  = regexp.MustCompile(`(?is)\bwhere\s+(?:\w+\.)?(id|customer_id|order_id)\s*=\s*'?(\d+)'?`)
	reCountAll = regexp.MustCompile(`(?is)^\s*select\s+count\s*\(\s*\*\s*\)\s+from\s`)
	reWrite    = regexp.MustCompile(`(?is)^\s*(insert|update|delete|drop|alter|create|truncate|grant|revoke|vacuum)\b`)
	rePriv     = regexp.MustCompile(`(?is)\bcopy\b.*\b(program|to\s+'|from\s+')|pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export|dblink|pg_shadow|pg_authid`)
	reInfoCols = regexp.MustCompile(`(?is)information_schema\.columns.*table_name\s*=\s*'(\w+)'`)
)

// Run answers one statement from the fake dataset. Nothing is executed.
func (d *Dataset) Run(q, user, db string) Result {
	s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(q), ";"))
	l := strings.ToLower(s)
	switch {
	case s == "":
		return Result{Tag: "EMPTY", Kind: "session"}
	case rePriv.MatchString(s):
		return Result{Kind: "admin", Err: &PGError{"42501", "permission denied: must be superuser or a member of pg_read_server_files"}}
	case reWrite.MatchString(s):
		verb := strings.ToLower(reWrite.FindStringSubmatch(s)[1])
		t := tableOf(s)
		if verb == "insert" || verb == "update" || verb == "delete" || verb == "truncate" {
			if t == "" {
				t = firstWordAfter(l, verb)
			}
			return Result{Kind: "write", Table: t, Err: &PGError{"42501", fmt.Sprintf("permission denied for table %s", t)}}
		}
		return Result{Kind: "admin", Err: &PGError{"42501", "permission denied for schema public"}}
	case strings.HasPrefix(l, "begin") || strings.HasPrefix(l, "start transaction"):
		return Result{Tag: "BEGIN", Kind: "session"}
	case strings.HasPrefix(l, "commit") || strings.HasPrefix(l, "end"):
		return Result{Tag: "COMMIT", Kind: "session"}
	case strings.HasPrefix(l, "rollback"):
		return Result{Tag: "ROLLBACK", Kind: "session"}
	case strings.HasPrefix(l, "set "), strings.HasPrefix(l, "reset "), strings.HasPrefix(l, "discard "):
		return Result{Tag: "SET", Kind: "session"}
	case strings.HasPrefix(l, "show "):
		return d.show(strings.TrimSpace(l[5:]))
	case strings.Contains(l, "pg_catalog.pg_database") || strings.Contains(l, "from pg_database"):
		return rows("recon", []string{"Name", "Owner", "Encoding", "Collate", "Ctype", "Access privileges"},
			[]string{"orders", "app", "UTF8", "en_US.UTF-8", "en_US.UTF-8", ""},
			[]string{"postgres", "postgres", "UTF8", "en_US.UTF-8", "en_US.UTF-8", ""},
			[]string{"template0", "postgres", "UTF8", "en_US.UTF-8", "en_US.UTF-8", "=c/postgres"},
			[]string{"template1", "postgres", "UTF8", "en_US.UTF-8", "en_US.UTF-8", "=c/postgres"})
	case strings.Contains(l, "pg_catalog.pg_class") || strings.Contains(l, "pg_tables"):
		var out [][]string
		for _, n := range d.Order {
			out = append(out, []string{"public", n, "table", "app"})
		}
		return rows("recon", []string{"Schema", "Name", "Type", "Owner"}, out...)
	case strings.Contains(l, "pg_user") || strings.Contains(l, "pg_roles"):
		return rows("recon", []string{"usename", "usesuper", "usecreatedb"},
			[]string{"postgres", "t", "t"}, []string{"app", "f", "f"}, []string{"replicator", "f", "f"})
	case reInfoCols.MatchString(s):
		t := strings.ToLower(reInfoCols.FindStringSubmatch(s)[1])
		tab, ok := d.Tables[t]
		if !ok {
			return rows("recon", []string{"column_name", "data_type"})
		}
		var out [][]string
		for _, c := range tab.Columns {
			out = append(out, []string{c, "text"})
		}
		return rows("recon", []string{"column_name", "data_type"}, out...)
	case strings.Contains(l, "information_schema.tables"):
		var out [][]string
		for _, n := range d.Order {
			out = append(out, []string{"public", n})
		}
		return rows("recon", []string{"table_schema", "table_name"}, out...)
	case strings.HasPrefix(l, "select") && !strings.Contains(l, " from "):
		return d.scalar(s, l, user, db)
	case strings.HasPrefix(l, "select") || strings.HasPrefix(l, "table "):
		return d.selectFrom(s, l)
	}
	return Result{Kind: "unknown", Err: &PGError{"42601", fmt.Sprintf("syntax error at or near %q", firstToken(s))}}
}

func (d *Dataset) scalar(s, l, user, db string) Result {
	expr := strings.TrimSpace(s[len("select"):])
	name := strings.ToLower(strings.Trim(strings.SplitN(expr, "(", 2)[0], " "))
	switch {
	case strings.Contains(l, "version()"):
		return rows("recon", []string{"version"}, []string{"PostgreSQL " + serverVersion + " on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, 64-bit"})
	case strings.Contains(l, "current_user") || strings.Contains(l, "session_user") || name == "user":
		return rows("recon", []string{"current_user"}, []string{user})
	case strings.Contains(l, "current_database()"):
		return rows("recon", []string{"current_database"}, []string{db})
	case strings.Contains(l, "current_schema"):
		return rows("recon", []string{"current_schema"}, []string{"public"})
	case strings.Contains(l, "inet_server_addr()"):
		return rows("recon", []string{"inet_server_addr"}, []string{d.Persona.InternalIP})
	case strings.Contains(l, "now()") || strings.Contains(l, "current_timestamp"):
		return rows("session", []string{"now"}, []string{"2026-10-31 21:30:00.000000+05:30"})
	}
	if n, err := strconv.Atoi(expr); err == nil {
		return rows("session", []string{"?column?"}, []string{strconv.Itoa(n)})
	}
	return Result{Kind: "unknown", Err: &PGError{"42883", fmt.Sprintf("function %s does not exist", truncate(expr, 60))}}
}

func (d *Dataset) selectFrom(s, l string) Result {
	t := tableOf(s)
	tab, ok := d.Tables[t]
	if !ok {
		return Result{Kind: "read", Table: t, Err: &PGError{"42P01", fmt.Sprintf("relation %q does not exist", t)}}
	}
	if reCountAll.MatchString(s) {
		return Result{Columns: []string{"count"}, Rows: [][]string{{strconv.Itoa(len(tab.Rows))}}, Tag: "SELECT 1", Kind: "read", Table: t}
	}
	cols, idx := tab.Columns, allIdx(len(tab.Columns))
	if m := reSelect.FindStringSubmatch(s); m != nil && strings.TrimSpace(m[1]) != "*" {
		var want []string
		var wi []int
		for _, c := range strings.Split(m[1], ",") {
			c = strings.ToLower(strings.Trim(strings.TrimSpace(c), `"`))
			if i := strings.LastIndex(c, "."); i >= 0 {
				c = c[i+1:]
			}
			j := indexOf(tab.Columns, c)
			if j < 0 {
				return Result{Kind: "read", Table: t, Err: &PGError{"42703", fmt.Sprintf("column %q does not exist", c)}}
			}
			want, wi = append(want, c), append(wi, j)
		}
		cols, idx = want, wi
	}
	var out [][]string
	where := reWhereID.FindStringSubmatch(s)
	for _, r := range tab.Rows {
		if where != nil {
			j := indexOf(tab.Columns, strings.ToLower(where[1]))
			if j < 0 || r[j] != where[2] {
				continue
			}
		}
		row := make([]string, len(idx))
		for k, j := range idx {
			row[k] = r[j]
		}
		out = append(out, row)
	}
	if m := reLimit.FindStringSubmatch(l); m != nil {
		if n, _ := strconv.Atoi(m[1]); n < len(out) {
			out = out[:n]
		}
	}
	return Result{Columns: cols, Rows: out, Tag: fmt.Sprintf("SELECT %d", len(out)), Kind: "read", Table: t}
}

func (d *Dataset) show(name string) Result {
	vals := map[string]string{"server_version": serverVersion, "data_directory": "/var/lib/postgresql/14/main",
		"port": "5432", "max_connections": "100", "timezone": "Asia/Kolkata", "ssl": "off", "listen_addresses": "*"}
	name = strings.TrimSuffix(name, ";")
	if name == "all" {
		var out [][]string
		for k, v := range vals {
			out = append(out, []string{k, v})
		}
		return rows("recon", []string{"name", "setting"}, out...)
	}
	if v, ok := vals[name]; ok {
		return rows("recon", []string{name}, []string{v})
	}
	if name == "hba_file" || name == "config_file" {
		return Result{Kind: "admin", Err: &PGError{"42501", "must be superuser or a member of pg_read_all_settings to examine " + name}}
	}
	return Result{Kind: "recon", Err: &PGError{"42704", fmt.Sprintf("unrecognized configuration parameter %q", name)}}
}

func rows(kind string, cols []string, rs ...[]string) Result {
	return Result{Columns: cols, Rows: rs, Tag: fmt.Sprintf("SELECT %d", len(rs)), Kind: kind}
}

// tableOf returns the first table after FROM (or after TABLE / INTO / UPDATE), without schema or quotes.
func tableOf(s string) string {
	var t string
	if m := reFrom.FindStringSubmatch(s); m != nil {
		t = m[1]
	} else {
		f := strings.Fields(s)
		for i := 0; i+1 < len(f); i++ {
			if w := strings.ToLower(f[i]); w == "table" || w == "into" || w == "update" {
				t = f[i+1]
				break
			}
		}
	}
	t = strings.ToLower(strings.Trim(t, `"();`))
	if i := strings.LastIndex(t, "."); i >= 0 {
		t = t[i+1:]
	}
	return t
}

func firstWordAfter(l, w string) string {
	f := strings.Fields(strings.TrimPrefix(l, w))
	if len(f) == 0 {
		return "?"
	}
	return strings.Trim(f[0], `"();`)
}

func firstToken(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return s
	}
	return truncate(f[0], 40)
}

func indexOf(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

func allIdx(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// splitStatements splits a simple-query string on semicolons outside single quotes.
func splitStatements(sql string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for _, r := range sql {
		switch {
		case r == '\'':
			inQ = !inQ
			b.WriteRune(r)
		case r == ';' && !inQ:
			if s := strings.TrimSpace(b.String()); s != "" {
				out = append(out, s)
			}
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		out = append(out, s)
	}
	return out
}
