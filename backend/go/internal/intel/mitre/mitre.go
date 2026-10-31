// Package mitre maps technique ids to names and tactics (07 §5). Never map without a firing rule.
package mitre

import (
	_ "embed"
	"encoding/csv"
	"sort"
	"strings"
)

//go:embed techniques.csv
var techniquesCSV string

type Technique struct {
	ID, Name, TacticID, Tactic string
}

var table = load()

func load() map[string]Technique {
	r := csv.NewReader(strings.NewReader(techniquesCSV))
	r.Comment = '#'
	rows, err := r.ReadAll()
	if err != nil {
		panic("mitre: bad techniques.csv: " + err.Error())
	}
	m := make(map[string]Technique, len(rows))
	for _, row := range rows {
		m[row[0]] = Technique{ID: row[0], Name: row[1], TacticID: row[2], Tactic: row[3]}
	}
	return m
}

// Lookup returns the technique, or ok=false for an unknown id.
func Lookup(id string) (Technique, bool) {
	t, ok := table[id]
	return t, ok
}

// All returns every technique in the table (the LLM fallback's allow-list), sorted by id.
func All() []Technique {
	out := make([]Technique, 0, len(table))
	for _, t := range table {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// KillChainOrder lists tactics in the order the ATT&CK panel shows them.
var KillChainOrder = []string{"TA0043", "TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0007", "TA0008", "TA0011", "TA0010", "TA0040"}
