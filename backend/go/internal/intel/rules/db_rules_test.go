package rules

import "testing"

func TestDBDecoyRules(t *testing.T) {
	set, err := Load("../../../rules/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		data map[string]any
		want string
	}{
		"recon":  {map[string]any{"query": "select version()", "kind": "recon"}, "db_recon"},
		"read":   {map[string]any{"query": "SELECT * FROM payments", "kind": "read", "table": "payments"}, "db_data_read"},
		"hashes": {map[string]any{"query": "select * from staff_users", "kind": "read", "table": "staff_users"}, "db_credential_dump"},
		"priv":   {map[string]any{"query": "COPY customers TO PROGRAM 'id'", "kind": "admin"}, "db_privileged"},
		"tamper": {map[string]any{"query": "DROP TABLE orders", "kind": "admin"}, "db_tamper"},
	}
	for name, c := range cases {
		found := false
		for _, m := range set.Evaluate("event", Input{Type: "db.query", Data: c.data}) {
			if m.Rule.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: rule %s did not fire", name, c.want)
		}
	}
}
