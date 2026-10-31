package maze

import (
	"math/rand/v2"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func graph(t *testing.T) *Graph {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	g, err := Load(filepath.Join(filepath.Dir(file), "..", "..", "maze", "maze.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var now = time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

// Safety invariant (08): a hidden node is never served to an unknown actor.
func TestUnknownActorSeesOnlyDefaults(t *testing.T) {
	g := graph(t)
	v := g.Visible(State{})
	for _, id := range []string{"lure_kubeconfig", "lure_db", "lure_ci_secret"} {
		if slices.Contains(v, id) {
			t.Fatalf("hidden node %s visible to unknown actor: %v", id, v)
		}
	}
	for _, id := range []string{"web_entry", "lure_backup", "ssh_entry", "lure_aws"} {
		if !slices.Contains(v, id) {
			t.Fatalf("default node %s missing: %v", id, v)
		}
	}
}

func TestInterestThenUnlock(t *testing.T) {
	g := graph(t)
	in := g.Interest(`find / -name "*.kube*"`, nil)
	if in["k8s"] != 3 {
		t.Fatalf("interest %v", in)
	}
	st := State{Nodes: map[string]string{"ssh_entry": "visited"}}
	id, reason, ok := g.Unlock(st, in, "k8s", now, true)
	if !ok || id != "lure_kubeconfig" || reason == "" {
		t.Fatalf("got %q %q %v", id, reason, ok)
	}
	if _, _, ok := g.Unlock(st, map[string]int{"k8s": 2}, "k8s", now, true); ok {
		t.Fatal("unlock below interest 3")
	}
	if _, _, ok := g.Unlock(st, in, "k8s", now, false); ok {
		t.Fatal("MAZE_ADAPTIVE=false must never unlock")
	}
	if _, _, ok := g.Unlock(State{Nodes: map[string]string{}}, in, "k8s", now, true); ok {
		t.Fatal("unlock without reaching the parent")
	}
}

// Property (08): unlock count per actor never exceeds limits, whatever the events.
func TestUnlockLimitsHoldUnderRandomEvents(t *testing.T) {
	g := graph(t)
	texts := []string{"kubectl get pods", "cat .env", "aws s3 ls", "jenkins", "ls", "mysql -u root", "helm list", ".git/config"}
	r := rand.New(rand.NewPCG(1, 2))
	for run := 0; run < 200; run++ {
		st := State{Nodes: map[string]string{"ssh_entry": "visited", "web_entry": "visited"}}
		interest := map[string]int{}
		tm := now
		for i := 0; i < 100; i++ {
			tm = tm.Add(time.Duration(r.IntN(120)) * time.Second)
			interest = g.Interest(texts[r.IntN(len(texts))], interest)
			if id, _, ok := g.Unlock(st, interest, "", tm, true); ok {
				st.Nodes[id] = "visible"
				st.Unlocks = append(st.Unlocks, tm)
				if r.IntN(2) == 0 {
					st.Nodes[id] = "visited"
				}
			}
			recent := 0
			for _, u := range st.Unlocks {
				if tm.Sub(u) < 10*time.Minute {
					recent++
				}
			}
			if recent > g.Limits.UnlocksPer10Min || len(st.Unlocks) > g.Limits.MaxDepth {
				t.Fatalf("limits broken: recent=%d total=%d", recent, len(st.Unlocks))
			}
		}
	}
}

func TestStretchNodesNeverUnlock(t *testing.T) {
	g := graph(t)
	st := State{Nodes: map[string]string{"ssh_entry": "visited", "lure_db": "visited", "svc_k8s": "visited", "lure_ci_secret": "visited"}}
	for i := 0; i < 10; i++ {
		id, _, ok := g.Unlock(st, map[string]int{"db": 50, "ci": 50, "k8s": 50, "cloud": 50}, "", now.Add(time.Duration(i)*time.Hour), true)
		if !ok {
			break
		}
		if n, _ := g.Node(id); n.Stretch {
			t.Fatalf("stretch node %s unlocked", id)
		}
		st.Nodes[id] = "visited"
		st.Unlocks = append(st.Unlocks, now.Add(time.Duration(i)*time.Hour))
	}
}

func TestOutStates(t *testing.T) {
	g := graph(t)
	out := g.Out(&State{Nodes: map[string]string{"lure_kubeconfig": "visible", "ssh_entry": "visited"}}, "a1")
	states := map[string]string{}
	for _, n := range out.Nodes {
		states[n.ID] = n.State
	}
	if states["lure_kubeconfig"] != "visible" || states["ssh_entry"] != "visited" || states["lure_db"] != "hidden" || states["web_entry"] != "visible" {
		t.Fatalf("%v", states)
	}
	if def := g.Out(nil, ""); def.Nodes[0].State != "" {
		t.Fatal("definition graph carries no state")
	}
	if g.NodeForToken("tok_kube") != "lure_kubeconfig" {
		t.Fatal("token -> node")
	}
}
