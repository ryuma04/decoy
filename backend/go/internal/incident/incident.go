// Package incident keeps one incident per actor (09): opened when the actor first reaches medium, updated on
// every score change, severity only rising automatically. Sending to Discord/Slack goes through Notify,
// which is not built yet (docs/17 row 8); until then decisions are logged and incidents still show in the UI.
package incident

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/alert"
	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/dto"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// Incident matches `Incident` in 04 §B.
type Incident = alert.Incident

// NotifyFunc sends one notification on the chosen channel. Nil = log only.
type NotifyFunc = alert.NotifyFunc

type Manager struct {
	Store  *store.Store
	Bus    bus.Bus
	Notify NotifyFunc
	Now    func() time.Time
}

// Run listens for actor score changes.
func (m *Manager) Run(ctx context.Context) {
	ch, stop := m.Bus.Subscribe(1000, bus.TopicActor)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if a, ok := msg.Value.(dto.ActorSummary); ok {
				if err := m.Handle(ctx, a); err != nil {
					slog.Error("incident update failed", "actor", a.Label, "err", err)
				}
			}
		}
	}
}

// Handle opens or updates the actor's incident.
func (m *Manager) Handle(ctx context.Context, a dto.ActorSummary) error {
	existing, err := m.Store.IncidentOfActor(ctx, a.ActorID)
	hasIncident := err == nil
	if !hasIncident && !alert.OpensIncident(a.Severity) {
		return nil
	}
	sev := a.Severity
	if hasIncident {
		sev = alert.Raise(existing.Severity, a.Severity)
	}
	title, err := m.title(ctx, a, sev)
	if err != nil {
		return err
	}
	row, created, err := m.Store.UpsertIncident(ctx, a.ActorID, sev, title)
	if err != nil {
		return err
	}
	inc := FromRow(row, a.Label, a.RiskScore)
	m.Bus.Publish(bus.TopicIncident, inc)
	if created {
		slog.Info("incident opened", "incident", row.IncidentID, "actor", a.Label, "severity", sev)
	}

	st := alert.NotifyState{NotifiedAt: row.NotifiedAt}
	if row.NotifiedSeverity != nil {
		st.NotifiedSeverity = *row.NotifiedSeverity
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	channel := alert.Decide(sev, st, now)
	if channel == alert.None {
		return nil
	}
	if m.Notify == nil {
		slog.Info("notification due (no notifier configured)", "incident", row.IncidentID, "severity", sev, "channel", channel)
	} else if err := m.Notify(ctx, channel, inc, a); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	return m.Store.MarkNotified(ctx, row.IncidentID, sev)
}

// title follows 09: "<severity>: <top finding title> by <ACT-xxxx> (<n> services)".
func (m *Manager) title(ctx context.Context, a dto.ActorSummary, sev string) (string, error) {
	fs, err := m.Store.FindingsOfActor(ctx, a.ActorID)
	if err != nil {
		return "", err
	}
	top := "Suspicious activity"
	best := -1
	for _, f := range fs {
		if f.Points > best {
			best, top = f.Points, f.Title
		}
	}
	n := len(a.Services)
	unit := "services"
	if n == 1 {
		unit = "service"
	}
	return fmt.Sprintf("%s: %s by %s (%d %s)", strings.ToUpper(sev[:1])+sev[1:], top, a.Label, n, unit), nil
}

func FromRow(r store.IncidentRow, label string, risk int) Incident {
	inc := Incident{IncidentID: r.IncidentID, ActorLabel: label, Severity: r.Severity, Status: r.Status, Title: r.Title,
		OpenedAt: r.OpenedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), RiskScore: risk}
	if r.ActorID != nil {
		inc.ActorID = *r.ActorID
	}
	return inc
}
