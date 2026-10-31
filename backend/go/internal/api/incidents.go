package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/dto"
	"github.com/ryuma04/decoy/backend/internal/incident"
	"github.com/ryuma04/decoy/backend/internal/intel/mitre"
	"github.com/ryuma04/decoy/backend/internal/intel/risk"
	"github.com/ryuma04/decoy/backend/internal/narrate"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// IncidentRoutes registers 04 §B incident endpoints, feedback and Explain. Needs s.DB.
func (s *Server) IncidentRoutes(mux *http.ServeMux) {
	authed := func(h http.HandlerFunc) http.HandlerFunc { return s.Auth.Require(false, h) }
	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.Auth.Require(true, h) }
	mux.HandleFunc("GET /v1/incidents", authed(s.listIncidents))
	mux.HandleFunc("GET /v1/incidents/{id}", authed(s.getIncident))
	mux.HandleFunc("PATCH /v1/incidents/{id}", authed(s.patchIncident))
	mux.HandleFunc("POST /v1/incidents/{id}/actions", admin(s.incidentAction))
	mux.HandleFunc("GET /v1/incidents/{id}/report", authed(s.incidentReport))
	mux.HandleFunc("POST /v1/incidents/{id}/feedback", authed(s.incidentFeedback))
	mux.HandleFunc("GET /v1/events/{event_id}/explain", authed(s.explainEvent))
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := s.DB.ListIncidents(r.Context(), q.Get("status"), q.Get("severity"), 100)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	items := []incident.Incident{}
	for _, row := range rows {
		a, err := s.DB.Actor(r.Context(), deref(row.ActorID))
		if err != nil {
			continue
		}
		items = append(items, incident.FromRow(row, a.Label, a.RiskScore))
	}
	writeJSON(w, http.StatusOK, newList(items, ""))
}

type recommended struct {
	Action string `json:"action"`
	Target string `json:"target"`
	Why    string `json:"why"`
}

type incidentDetail struct {
	incident.Incident
	Summary            string              `json:"summary"`
	SummarySrc         string              `json:"summary_src"`
	Narrative          *narrate.Narrative  `json:"narrative"`
	Actor              dto.ActorSummary    `json:"actor"`
	Findings           []dto.Finding       `json:"findings"`
	IOCs               []map[string]string `json:"iocs"`
	Actions            []map[string]any    `json:"actions"`
	Notes              []map[string]any    `json:"notes"`
	RecommendedActions []recommended       `json:"recommended_actions"`
}

func (s *Server) loadIncident(w http.ResponseWriter, r *http.Request) (store.IncidentRow, store.Actor, bool) {
	row, err := s.DB.Incident(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && row.ActorID == nil) {
		writeError(w, http.StatusNotFound, "not_found", "incident not found")
		return row, store.Actor{}, false
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return row, store.Actor{}, false
	}
	a, err := s.DB.Actor(r.Context(), *row.ActorID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return row, a, false
	}
	return row, a, true
}

// recommend maps findings to lab response actions (09 §Recommended actions).
func recommend(findings []store.FindingRow, sum dto.ActorSummary, tokensUsed []string, sessions []store.SessionRow) []recommended {
	out := []recommended{}
	has := map[string]bool{}
	for _, f := range findings {
		has[f.RuleID] = true
	}
	for _, ip := range sum.IPs {
		if len(has) > 0 {
			out = append(out, recommended{"block_ip", ip, "Stop further activity from this source on the decoys."})
		}
	}
	for _, t := range tokensUsed {
		out = append(out, recommended{"rotate_token", t, "The honeytoken was used; burn it and plant a fresh one."})
	}
	if has["ssh_persistence"] || has["cron_persistence"] {
		for _, se := range sessions {
			if se.EndedAt == nil && se.Service == "ssh" {
				out = append(out, recommended{"kill_session", se.SensorSessionID, "Persistence was attempted in this live session."})
			}
		}
	}
	return out
}

func (s *Server) facts(r *http.Request, a store.Actor, sum dto.ActorSummary, findings []store.FindingRow, rec []recommended, incidentID string) narrate.Facts {
	f := narrate.Facts{ActorLabel: a.Label, Severity: a.Severity, Risk: a.RiskScore, Behaviour: a.BehaviourClass,
		Services: sum.Services, IPs: sum.IPs, TouchedProduction: a.TouchedProduction, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen,
		DashboardURL: s.DashboardURL + "/incidents/" + incidentID}
	for _, x := range findings {
		f.Findings = append(f.Findings, narrate.Finding{Title: x.Title, Technique: deref(x.Technique), TS: x.TS})
	}
	for _, x := range rec {
		f.Recommended = append(f.Recommended, x.Action+" "+x.Target)
	}
	return f
}

func (s *Server) buildIncident(r *http.Request, row store.IncidentRow, a store.Actor, withLLM bool) (incidentDetail, error) {
	ctx := r.Context()
	sum, err := dto.Summary(ctx, s.DB, a)
	if err != nil {
		return incidentDetail{}, err
	}
	findings, _ := s.DB.FindingsOfActor(ctx, a.ActorID)
	sessions, _ := s.DB.SessionsOfActor(ctx, a.ActorID)
	iocs, _ := s.DB.IOCs(ctx, a.ActorID)
	actions, _ := s.DB.Actions(ctx, row.IncidentID)
	notes, _ := s.DB.Notes(ctx, row.IncidentID)
	used := []string{}
	for _, i := range iocs {
		if i.Kind == "token" {
			used = append(used, i.Value)
		}
	}
	rec := recommend(findings, sum, used, sessions)
	f := s.facts(r, a, sum, findings, rec, row.IncidentID)
	f.Tokens = used
	var nar narrate.Narrative
	if withLLM {
		nar = s.Narrator.Narrate(ctx, "incident", row.IncidentID, f, nil, 5*time.Second)
	} else {
		nar = narrate.Template(f)
	}
	d := incidentDetail{Incident: incident.FromRow(row, a.Label, a.RiskScore), Summary: nar.Text, SummarySrc: nar.Source,
		Narrative: &nar, Actor: sum, Findings: []dto.Finding{}, IOCs: []map[string]string{}, Actions: []map[string]any{},
		Notes: []map[string]any{}, RecommendedActions: rec}
	for _, x := range findings {
		d.Findings = append(d.Findings, dto.FromFinding(x))
	}
	for _, i := range iocs {
		d.IOCs = append(d.IOCs, map[string]string{"kind": i.Kind, "value": i.Value})
	}
	for _, x := range actions {
		d.Actions = append(d.Actions, map[string]any{"action_id": x.ActionID, "action": x.Action, "target": x.Target,
			"status": x.Status, "requested_by": x.RequestedBy, "ts": x.TS.UTC()})
	}
	for _, n := range notes {
		d.Notes = append(d.Notes, map[string]any{"author": n.Author, "body": n.Body, "ts": n.TS.UTC()})
	}
	return d, nil
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	row, a, ok := s.loadIncident(w, r)
	if !ok {
		return
	}
	d, err := s.buildIncident(r, row, a, true)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	_ = s.DB.SetIncidentSummary(r.Context(), row.IncidentID, d.Summary, d.SummarySrc)
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) patchIncident(w http.ResponseWriter, r *http.Request) {
	row, a, ok := s.loadIncident(w, r)
	if !ok {
		return
	}
	var body struct {
		Status *string `json:"status"`
		Note   *string `json:"note"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Status != nil {
		switch *body.Status {
		case "open", "ack", "contained", "closed":
		default:
			writeError(w, http.StatusBadRequest, "bad_request", "status must be open, ack, contained or closed")
			return
		}
		if err := s.DB.SetIncidentStatus(r.Context(), row.IncidentID, *body.Status); err != nil {
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
			return
		}
	}
	if body.Note != nil && strings.TrimSpace(*body.Note) != "" {
		if err := s.DB.AddNote(r.Context(), row.IncidentID, CurrentUser(r).UserID, strings.TrimSpace(*body.Note)); err != nil {
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
			return
		}
	}
	row, _ = s.DB.Incident(r.Context(), row.IncidentID)
	d, err := s.buildIncident(r, row, a, false)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	s.Bus.Publish("incident", d.Incident)
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) incidentAction(w http.ResponseWriter, r *http.Request) {
	row, _, ok := s.loadIncident(w, r)
	if !ok {
		return
	}
	var body struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Target = strings.TrimSpace(body.Target)
	switch body.Action {
	case "block_ip", "unblock_ip":
		if net.ParseIP(body.Target) == nil {
			writeError(w, http.StatusBadRequest, "bad_request", "target must be an IP address")
			return
		}
	case "kill_session", "rotate_token":
		if body.Target == "" || len(body.Target) > 200 {
			writeError(w, http.StatusBadRequest, "bad_request", "target is required")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "action must be block_ip, unblock_ip, kill_session or rotate_token")
		return
	}
	act, err := s.DB.ApplyAction(r.Context(), row.IncidentID, body.Action, body.Target, CurrentUser(r).UserID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "action not applied; try again")
		return
	}
	out := map[string]any{"action_id": act.ActionID, "action": act.Action, "target": act.Target, "status": act.Status,
		"requested_by": CurrentUser(r).Email, "ts": act.TS.UTC()}
	s.Bus.Publish("incident", out)
	writeJSON(w, http.StatusOK, out)
}

var fixes = map[string]string{
	"T1552.001": "Scan repositories and hosts for plaintext credentials; move secrets to a secrets manager.",
	"T1552.007": "Restrict secret access in Kubernetes RBAC; audit service-account tokens.",
	"T1078":     "Rotate the affected credentials; review sign-ins for the same accounts.",
	"T1110.001": "Enforce MFA and lockout on exposed logins.",
	"T1110.004": "Enforce MFA; check for reused passwords against breach lists.",
	"T1190":     "Patch and validate input on public-facing apps; add a WAF rule for the payload family.",
	"T1105":     "Restrict outbound downloads from servers; alert on new executables.",
	"T1098.004": "Monitor authorized_keys changes; manage keys centrally.",
	"T1053.003": "Monitor crontab changes; restrict who can edit cron.",
	"T1027":     "Alert on decode-and-execute command patterns.",
	"T1613":     "Disable anonymous Kubernetes API access; restrict list permissions.",
	"T1082":     "Expected recon; correlate with later stages before acting.",
	"T1087.001": "Expected recon; correlate with later stages before acting.",
	"T1046":     "Limit exposed ports; rate-limit connection attempts at the edge.",
	"T1059.004": "Restrict interactive shell access; require MFA for SSH.",
}

func (s *Server) incidentReport(w http.ResponseWriter, r *http.Request) {
	row, a, ok := s.loadIncident(w, r)
	if !ok {
		return
	}
	d, err := s.buildIncident(r, row, a, false)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, d)
		return
	}
	if row.Summary != nil && *row.Summary != "" {
		d.Summary = *row.Summary
		if row.SummarySrc != nil {
			d.SummarySrc = *row.SummarySrc
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Incident report — %s\n\n", d.Title)
	fmt.Fprintf(&b, "| Field | Value |\n| --- | --- |\n| Incident | %s |\n| Actor | %s |\n| Severity | %s |\n| Risk | %d / 100 |\n| Status | %s |\n| Time range | %s – %s |\n\n",
		d.IncidentID, d.ActorLabel, d.Severity, d.RiskScore, d.Status, a.FirstSeen.UTC().Format(time.RFC3339), a.LastSeen.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "## Summary (%s)\n\n%s\n\n", d.SummarySrc, d.Summary)
	b.WriteString("## ATT&CK techniques\n\n| Technique | Name | Tactic | Evidence | First seen |\n| --- | --- | --- | --- | --- |\n")
	type agg struct {
		n     int
		first time.Time
	}
	techs := map[string]*agg{}
	for _, f := range d.Findings {
		if f.Technique == nil {
			continue
		}
		t := techs[*f.Technique]
		if t == nil {
			t = &agg{first: f.TS}
			techs[*f.Technique] = t
		}
		t.n += len(f.Evidence.EventIDs)
		if f.TS.Before(t.first) {
			t.first = f.TS
		}
	}
	ids := make([]string, 0, len(techs))
	for id := range techs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m, _ := mitre.Lookup(id)
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", id, m.Name, m.Tactic, techs[id].n, techs[id].first.UTC().Format(time.RFC3339))
	}
	b.WriteString("\n## Timeline (findings)\n\n")
	for i, f := range d.Findings {
		if i == 50 {
			break
		}
		fmt.Fprintf(&b, "- %s — %s (%s, %d pts, %s)\n", f.TS.UTC().Format(time.RFC3339), f.Title, deref(f.Technique), f.Points, f.Source)
	}
	sessions, _ := s.DB.SessionsOfActor(r.Context(), a.ActorID)
	b.WriteString("\n## Linked sessions\n\n| Session | Service | Source IP | Link score | Reasons |\n| --- | --- | --- | --- | --- |\n")
	for _, se := range sessions {
		ds := dto.FromSession(se)
		reasons := []string{}
		for _, lr := range ds.LinkReasons {
			reasons = append(reasons, fmt.Sprintf("%s %.2f", lr.Signal, lr.Weight))
		}
		score := "first"
		if ds.LinkScore != nil && len(ds.LinkReasons) > 0 {
			score = fmt.Sprintf("%.2f", *ds.LinkScore)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", ds.SensorSessionID, ds.Service, ds.SrcIP, score, strings.Join(reasons, ", "))
	}
	b.WriteString("\n## Indicators\n\n| Kind | Value |\n| --- | --- |\n")
	for _, i := range d.IOCs {
		fmt.Fprintf(&b, "| %s | `%s` |\n", i["kind"], strings.ReplaceAll(i["value"], "|", "\\|"))
	}
	b.WriteString("\n## Actions taken\n\n")
	if len(d.Actions) == 0 {
		b.WriteString("None.\n")
	}
	for _, x := range d.Actions {
		fmt.Fprintf(&b, "- %v %v (%v, by %v)\n", x["action"], x["target"], x["status"], x["requested_by"])
	}
	b.WriteString("\n## Recommended fixes\n\n")
	for _, id := range ids {
		if fx, ok := fixes[id]; ok {
			fmt.Fprintf(&b, "- **%s**: %s\n", id, fx)
		}
	}
	b.WriteString("\n---\nCorrelation is behavioural association (\"likely same operator\"), not identity. Lab environment.\n")
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="incident-%s.md"`, d.ActorLabel))
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) incidentFeedback(w http.ResponseWriter, r *http.Request) {
	row, a, ok := s.loadIncident(w, r)
	if !ok {
		return
	}
	var body struct {
		Label           string `json:"label"`
		AllowlistSource bool   `json:"allowlist_source"`
		Note            string `json:"note"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	y := 0.0
	switch body.Label {
	case "confirmed":
		y = 1
	case "false_positive":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "label must be confirmed or false_positive")
		return
	}
	ctx := r.Context()
	cur, err := s.DB.ActiveWeights(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	w0 := risk.Weights{Version: cur.Version, W: cur.Weights, Bias: cur.Bias, LearningRate: cur.LearningRate}
	before := risk.Score(a.StageScores, w0, risk.Facts{})
	fbID, err := s.DB.AddFeedback(ctx, store.Feedback{ActorID: a.ActorID, IncidentID: row.IncidentID, Label: int(y),
		StageScores: a.StageScores, Features: map[string]any{}, PredictedP: before.P, Author: CurrentUser(r).UserID,
		Allowlisted: body.AllowlistSource && y == 0})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	version := cur.Version
	newRisk := a.RiskScore
	if s.ScorerLearn {
		next := risk.Update(w0, a.StageScores, y)
		v, err := s.DB.SaveWeights(ctx, store.ScorerWeights{Weights: next.W, Bias: next.Bias, LearningRate: next.LearningRate, FeedbackID: &fbID})
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "weights not saved; try again")
			return
		}
		version = v
		next.Version = v
		newRisk = risk.Score(a.StageScores, next, risk.Facts{}).Risk
	}
	if body.AllowlistSource && y == 0 {
		sum, _ := dto.Summary(ctx, s.DB, a)
		for _, ip := range sum.IPs {
			_ = s.DB.AddAllowlist(ctx, ip+"/32", "false positive on incident "+row.IncidentID, CurrentUser(r).UserID)
		}
	}
	if strings.TrimSpace(body.Note) != "" {
		_ = s.DB.AddNote(ctx, row.IncidentID, CurrentUser(r).UserID, strings.TrimSpace(body.Note))
	}
	writeJSON(w, http.StatusOK, map[string]any{"feedback_id": fbID, "old_risk": a.RiskScore, "new_risk": newRisk,
		"weights_version": version})
}

func (s *Server) explainEvent(w http.ResponseWriter, r *http.Request) {
	ev, err := s.DB.GetEvent(r.Context(), r.PathValue("event_id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	e := toEvent(ev, false)
	f := narrate.Facts{ActorLabel: deref(ev.ActorLabel), Services: []string{ev.Service}, IPs: []string{ev.SrcIP},
		Tokens: e.Tokens, FirstSeen: ev.TS, LastSeen: ev.TS, DashboardURL: s.DashboardURL,
		Findings: []narrate.Finding{{Title: e.Type + ": " + e.Summary, TS: ev.TS}}}
	if f.ActorLabel == "" {
		f.ActorLabel = "An unlinked source"
	}
	nar := s.Narrator.Narrate(r.Context(), "event", ev.EventID, f, []string{e.Summary}, 5*time.Second)
	writeJSON(w, http.StatusOK, nar)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
