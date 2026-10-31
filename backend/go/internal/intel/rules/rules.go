// Package rules loads rules/rules.yaml and evaluates it against events and features (07 §4). Deterministic.
package rules

import (
	"fmt"
	"math"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

var Stages = []string{"recon", "access", "post_access", "lateral"}

type Rule struct {
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	Scope     string `yaml:"scope"`
	Stage     string `yaml:"stage"`
	Technique string `yaml:"technique"`
	Points    int    `yaml:"points"`
	Scale     string `yaml:"scale"`
	When      Cond   `yaml:"when"`
}

// Cond is one condition; all set fields must hold. Any/All nest further conditions.
type Cond struct {
	Type         string            `yaml:"type"`
	Types        []string          `yaml:"types"`
	EventType    string            `yaml:"event_type"`
	Regex        string            `yaml:"regex"`
	Argv0In      []string          `yaml:"argv0_in"`
	PathRegex    string            `yaml:"path_regex"`
	DataRegex    map[string]string `yaml:"data_regex"`
	Honeyfile    *bool             `yaml:"honeyfile"`
	Feature      string            `yaml:"feature"`
	Gte          *float64          `yaml:"gte"`
	InputLabel   string            `yaml:"input_label"`
	InputRiskGte *float64          `yaml:"input_risk_gte"`
	Any          []Cond            `yaml:"any"`
	All          []Cond            `yaml:"all"`

	re     *regexp.Regexp
	pathRe *regexp.Regexp
	dataRe map[string]*regexp.Regexp
}

// Input is what one evaluation sees.
type Input struct {
	Type      string
	Data      map[string]any
	Features  map[string]float64
	InputRisk *InputRisk // set for evaluated web inputs
	TokenSens int        // sensitivity of the used token (token.used)
}

type InputRisk struct {
	Label  string
	Risk   float64
	Source string // rule | ml | rule+ml
}

// Match is a fired rule, ready to become a finding.
type Match struct {
	Rule       *Rule
	Points     int
	Confidence float64
	Source     string
	Matched    string
}

type Set struct{ Rules []*Rule }

// Load parses and compiles a rules file.
func Load(file string) (*Set, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Set, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		switch {
		case r.ID == "" || seen[r.ID]:
			return nil, fmt.Errorf("rules: missing or duplicate id %q", r.ID)
		case !slices.Contains([]string{"event", "session", "actor"}, r.Scope):
			return nil, fmt.Errorf("rules: %s: bad scope %q", r.ID, r.Scope)
		case !slices.Contains(Stages, r.Stage):
			return nil, fmt.Errorf("rules: %s: bad stage %q", r.ID, r.Stage)
		case r.Points <= 0:
			return nil, fmt.Errorf("rules: %s: points must be > 0", r.ID)
		}
		seen[r.ID] = true
		if err := compile(&r.When); err != nil {
			return nil, fmt.Errorf("rules: %s: %w", r.ID, err)
		}
	}
	return &Set{Rules: rs}, nil
}

func compile(c *Cond) error {
	var err error
	if c.Regex != "" {
		if c.re, err = regexp.Compile("(?i)" + c.Regex); err != nil {
			return err
		}
	}
	if c.PathRegex != "" {
		if c.pathRe, err = regexp.Compile("(?i)" + c.PathRegex); err != nil {
			return err
		}
	}
	if len(c.DataRegex) > 0 {
		c.dataRe = map[string]*regexp.Regexp{}
		for k, v := range c.DataRegex {
			if c.dataRe[k], err = regexp.Compile("(?i)" + v); err != nil {
				return err
			}
		}
	}
	for i := range c.Any {
		if err := compile(&c.Any[i]); err != nil {
			return err
		}
	}
	for i := range c.All {
		if err := compile(&c.All[i]); err != nil {
			return err
		}
	}
	return nil
}

// Evaluate returns every rule of the given scope that matches in.
func (s *Set) Evaluate(scope string, in Input) []Match {
	var out []Match
	for _, r := range s.Rules {
		if r.Scope != scope {
			continue
		}
		if ok, matched := r.When.eval(in); ok {
			out = append(out, r.match(in, matched))
		}
	}
	return out
}

func (r *Rule) match(in Input, matched string) Match {
	m := Match{Rule: r, Points: r.Points, Confidence: 1, Source: "rule", Matched: matched}
	switch r.Scale {
	case "input_risk":
		if in.InputRisk != nil {
			m.Points = int(math.Round(float64(r.Points) * in.InputRisk.Risk))
			m.Confidence = in.InputRisk.Risk
			m.Source = in.InputRisk.Source
		}
	case "token_sensitivity":
		sens := in.TokenSens
		if sens <= 0 {
			sens = 3
		}
		m.Points = r.Points * sens / 3
	}
	if m.Points < 1 {
		m.Points = 1
	}
	return m
}

func text(in Input) string {
	for _, k := range []string{"raw", "path", "value", "payload"} {
		if s, ok := in.Data[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func (c *Cond) eval(in Input) (bool, string) {
	matched := text(in)
	if c.Type != "" && in.Type != c.Type {
		return false, ""
	}
	if len(c.Types) > 0 && !slices.Contains(c.Types, in.Type) {
		return false, ""
	}
	if c.EventType != "" && in.Type != c.EventType {
		return false, ""
	}
	if c.re != nil && !c.re.MatchString(matched) {
		return false, ""
	}
	if len(c.Argv0In) > 0 {
		argv0, _ := in.Data["argv0"].(string)
		if !slices.Contains(c.Argv0In, path.Base(argv0)) {
			return false, ""
		}
	}
	if c.pathRe != nil && !c.pathRe.MatchString(pathArgs(in)) {
		return false, ""
	}
	for k, re := range c.dataRe {
		v, _ := in.Data[k].(string)
		if !re.MatchString(v) {
			return false, ""
		}
	}
	if c.Honeyfile != nil {
		id, _ := in.Data["honeyfile_id"].(string)
		if (id != "") != *c.Honeyfile {
			return false, ""
		}
	}
	if c.Feature != "" {
		v := in.Features[c.Feature]
		if c.Gte != nil && v < *c.Gte {
			return false, ""
		}
		matched = fmt.Sprintf("%s=%g", c.Feature, v)
	}
	if c.InputLabel != "" {
		if in.InputRisk == nil || in.InputRisk.Label != c.InputLabel {
			return false, ""
		}
		if c.InputRiskGte != nil && in.InputRisk.Risk < *c.InputRiskGte {
			return false, ""
		}
	}
	for _, sub := range c.All {
		if ok, _ := sub.eval(in); !ok {
			return false, ""
		}
	}
	if len(c.Any) > 0 {
		hit := false
		for _, sub := range c.Any {
			if ok, _ := sub.eval(in); ok {
				hit = true
				break
			}
		}
		if !hit {
			return false, ""
		}
	}
	if len(matched) > 300 {
		matched = matched[:300]
	}
	return true, matched
}

func pathArgs(in Input) string {
	parts := []string{}
	if p, ok := in.Data["path"].(string); ok {
		parts = append(parts, p)
	}
	if args, ok := in.Data["args"].([]any); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) == 0 {
		parts = append(parts, text(in))
	}
	return strings.Join(parts, " ")
}
