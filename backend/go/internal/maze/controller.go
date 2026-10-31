package maze

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// Message is published on the maze topic (04 SSE `maze`).
type Message struct {
	ActorID string `json:"actor_id"`
	NodeID  string `json:"node_id"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
}

// Controller applies the maze algorithm (08) to each event of an attributed actor.
type Controller struct {
	Graph    *Graph
	Store    *store.Store
	Bus      bus.Bus
	Adaptive bool
}

var entryOf = map[string]string{"web": "web_entry", "ssh": "ssh_entry", "k8s": "svc_k8s", "beacon": "svc_beacon", "db": "svc_db"}

// entryFor picks the maze entry an event belongs to. The Aetees divert proxy also reports service "web", so it is
// told apart by its sensor id (aetees-01) instead of landing on the admin web decoy's node.
func entryFor(ev store.StoredEvent) string {
	if strings.HasPrefix(ev.SensorID, "aetees") {
		return "aetees_entry"
	}
	return entryOf[ev.Service]
}

// Observe updates interest, marks visited nodes and maybe unlocks one node.
func (c *Controller) Observe(ctx context.Context, actorID string, ev store.StoredEvent, interest map[string]int) error {
	if c == nil || c.Graph == nil {
		return nil
	}
	d := map[string]any{}
	_ = json.Unmarshal(ev.Data, &d)
	text := ""
	for _, k := range []string{"raw", "path", "value", "resource", "query"} { // query: DB decoy statements
		if s, ok := d[k].(string); ok {
			text += " " + s
		}
	}
	next := c.Graph.Interest(text, interest)
	changed := false
	lastTheme := ""
	for k, v := range next {
		if v != interest[k] {
			changed = true
			lastTheme = k
		}
	}
	if changed {
		if err := c.Store.SetInterest(ctx, actorID, next); err != nil {
			return err
		}
	}

	nodes, unlocks, err := c.Store.MazeNodes(ctx, actorID)
	if err != nil {
		return err
	}
	visit := func(id, reason string) error {
		if id == "" || nodes[id] == "visited" {
			return nil
		}
		nodes[id] = "visited"
		if err := c.Store.SetMazeNode(ctx, actorID, id, "visited", ""); err != nil {
			return err
		}
		c.Bus.Publish(bus.TopicMaze, Message{ActorID: actorID, NodeID: id, State: "visited", Reason: reason})
		return nil
	}
	if err := visit(entryFor(ev), "connected to "+ev.Service); err != nil {
		return err
	}
	for _, k := range []string{"honeyfile_id", "token_id"} {
		if tok, ok := d[k].(string); ok && tok != "" {
			if err := visit(c.Graph.NodeForToken(tok), ev.Type+" "+tok); err != nil {
				return err
			}
		}
	}
	for _, tok := range ev.Tokens {
		if err := visit(c.Graph.NodeForToken(tok), ev.Type+" "+tok); err != nil {
			return err
		}
	}

	id, reason, ok := c.Graph.Unlock(State{Nodes: nodes, Unlocks: unlocks}, next, lastTheme, time.Now(), c.Adaptive)
	if !ok {
		return nil
	}
	if err := c.Store.SetMazeNode(ctx, actorID, id, "visible", reason); err != nil {
		return err
	}
	slog.Info("maze unlock", "actor", actorID, "node", id, "reason", reason)
	c.Bus.Publish(bus.TopicMaze, Message{ActorID: actorID, NodeID: id, State: "visible", Reason: reason})
	return nil
}

// View answers GET /v1/sensor/maze-view for one sensor session (04 §A).
func (c *Controller) View(ctx context.Context, sensorSessionID, service string) (map[string]any, error) {
	st := State{}
	actorID := any(nil)
	if s, err := c.Store.SessionBySensorID(ctx, sensorSessionID); err == nil && s.ActorID != nil {
		actorID = *s.ActorID
		nodes, unlocks, err := c.Store.MazeNodes(ctx, *s.ActorID)
		if err != nil {
			return nil, err
		}
		st = State{Nodes: nodes, Unlocks: unlocks}
	}
	visible := c.Graph.Visible(st)
	files := []map[string]string{}
	if lures, err := c.Store.LureFiles(ctx, service); err == nil {
		for _, id := range visible {
			if f, ok := lures[id]; ok {
				files = append(files, map[string]string{"path": f[0], "honeyfile_id": f[1], "maze_node": id})
			}
		}
	}
	secrets := []string{}
	for _, id := range visible {
		if id == "lure_ci_secret" {
			secrets = append(secrets, "ci-jenkins-token")
		}
		if id == "lure_db" {
			secrets = append(secrets, "db-credentials")
		}
	}
	return map[string]any{"actor_id": actorID, "visible_nodes": visible, "files": files, "k8s_secrets": secrets,
		"limits": map[string]any{"remaining_requests": 500, "session_deadline": time.Now().UTC().Add(30 * time.Minute)}}, nil
}
