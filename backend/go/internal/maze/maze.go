// Package maze is the adaptive deception maze (08): a fixed graph of lures and decoy services, per-actor
// interest, deterministic unlocks within hard limits, and the view each decoy may show.
package maze

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type Node struct {
	ID      string  `yaml:"id" json:"id"`
	Kind    string  `yaml:"kind" json:"kind"` // entry | lure | service
	Theme   *string `yaml:"theme" json:"theme"`
	Service *string `yaml:"service" json:"service"`
	Label   string  `yaml:"label" json:"label"`
	Token   string  `yaml:"token" json:"-"`
	Default string  `yaml:"default" json:"-"` // visible | hidden ("" = visible for entries/services)
	Stretch bool    `yaml:"stretch" json:"stretch"`
}

type Edge struct {
	From  string `yaml:"from" json:"from"`
	To    string `yaml:"to" json:"to"`
	Label string `yaml:"label" json:"label,omitempty"`
}

type Signal struct {
	Match  string `yaml:"match"`
	Theme  string `yaml:"theme"`
	Points int    `yaml:"points"`
	re     *regexp.Regexp
}

type Limits struct {
	MaxDepth        int `yaml:"max_depth"`
	UnlocksPer10Min int `yaml:"unlocks_per_10min"`
	LoopsPerTheme   int `yaml:"loops_per_theme"`
}

type Graph struct {
	Version int      `yaml:"version"`
	Themes  []string `yaml:"themes"`
	Nodes   []Node   `yaml:"nodes"`
	Edges   []Edge   `yaml:"edges"`
	Signals []Signal `yaml:"interest_signals"`
	Limits  Limits   `yaml:"limits"`
	byID    map[string]*Node
	parents map[string][]string
}

func Load(path string) (*Graph, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Graph, error) {
	var g Graph
	if err := yaml.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("maze: %w", err)
	}
	g.byID = map[string]*Node{}
	g.parents = map[string][]string{}
	for i := range g.Nodes {
		g.byID[g.Nodes[i].ID] = &g.Nodes[i]
	}
	for _, e := range g.Edges {
		if g.byID[e.From] == nil || g.byID[e.To] == nil {
			return nil, fmt.Errorf("maze: edge %s -> %s references an unknown node", e.From, e.To)
		}
		g.parents[e.To] = append(g.parents[e.To], e.From)
	}
	for i := range g.Signals {
		re, err := regexp.Compile("(?i)" + g.Signals[i].Match)
		if err != nil {
			return nil, fmt.Errorf("maze: signal %q: %w", g.Signals[i].Match, err)
		}
		g.Signals[i].re = re
	}
	if g.Limits.MaxDepth == 0 {
		g.Limits = Limits{MaxDepth: 6, UnlocksPer10Min: 3, LoopsPerTheme: 3}
	}
	return &g, nil
}

func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.byID[id]
	if !ok {
		return Node{}, false
	}
	return *n, true
}

// HiddenByDefault reports whether a node starts hidden.
func (g *Graph) HiddenByDefault(id string) bool {
	n := g.byID[id]
	return n != nil && n.Default == "hidden"
}

// Interest adds the points of every signal matching text (once per signal per event, 08 step 1).
func (g *Graph) Interest(text string, interest map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range interest {
		out[k] = v
	}
	for _, s := range g.Signals {
		if s.re.MatchString(text) {
			out[s.Theme] += s.Points
		}
	}
	return out
}

// NodeForToken returns the lure node that plants a token (for "visited" on read/use).
func (g *Graph) NodeForToken(token string) string {
	for _, n := range g.Nodes {
		if n.Token != "" && n.Token == token {
			return n.ID
		}
	}
	return ""
}

// State is one actor's maze: node -> hidden | visible | visited, plus unlock history for rate limits.
type State struct {
	Nodes   map[string]string
	Unlocks []time.Time
}

// Visible is the actor's view: default-visible nodes plus unlocked/visited ones. Unknown actor = defaults only.
func (g *Graph) Visible(st State) []string {
	var out []string
	for _, n := range g.Nodes {
		s := st.Nodes[n.ID]
		if s == "visible" || s == "visited" || (s == "" && n.Default != "hidden") {
			out = append(out, n.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Unlock decides at most one node to reveal (08 algorithm steps 3–5). adaptive=false never unlocks.
func (g *Graph) Unlock(st State, interest map[string]int, lastTheme string, now time.Time, adaptive bool) (string, string, bool) {
	if !adaptive {
		return "", "", false
	}
	recent := 0
	for _, t := range st.Unlocks {
		if now.Sub(t) < 10*time.Minute {
			recent++
		}
	}
	if recent >= g.Limits.UnlocksPer10Min || len(st.Unlocks) >= g.Limits.MaxDepth {
		return "", "", false
	}
	type cand struct {
		id, theme string
		score     int
	}
	var cands []cand
	for _, n := range g.Nodes {
		if n.Default != "hidden" || n.Theme == nil || n.Stretch {
			continue
		}
		if s := st.Nodes[n.ID]; s == "visible" || s == "visited" {
			continue
		}
		reachable := false
		for _, p := range g.parents[n.ID] {
			pn := g.byID[p]
			if st.Nodes[p] == "visited" || (pn.Kind == "entry" && st.Nodes[p] != "") {
				reachable = true
			}
		}
		if !reachable {
			continue
		}
		cands = append(cands, cand{n.ID, *n.Theme, interest[*n.Theme]})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		if (cands[i].theme == lastTheme) != (cands[j].theme == lastTheme) {
			return cands[i].theme == lastTheme
		}
		return cands[i].id < cands[j].id
	})
	if len(cands) == 0 || cands[0].score < 3 {
		return "", "", false
	}
	return cands[0].id, fmt.Sprintf("interest %s=%d", cands[0].theme, cands[0].score), true
}

// Definition is the JSON graph for GET /v1/maze and /v1/actors/{id}/maze (04 MazeGraph).
type GraphOut struct {
	Nodes   []NodeOut `json:"nodes"`
	Edges   []Edge    `json:"edges"`
	ActorID string    `json:"actor_id,omitempty"`
}

type NodeOut struct {
	Node
	State string `json:"state,omitempty"`
}

func (g *Graph) Out(st *State, actorID string) GraphOut {
	out := GraphOut{Edges: g.Edges, ActorID: actorID}
	for _, n := range g.Nodes {
		no := NodeOut{Node: n}
		if st != nil {
			switch s := st.Nodes[n.ID]; {
			case s != "":
				no.State = s
			case n.Default == "hidden":
				no.State = "hidden"
			default:
				no.State = "visible"
			}
		}
		out.Nodes = append(out.Nodes, no)
	}
	return out
}
