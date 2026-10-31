// Package alert turns incident changes into notifications (09): who gets told, when, and with what text.
package alert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/dto"
	"github.com/ryuma04/decoy/backend/internal/narrate"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// Notification is the unit of alert dispatch.
type Notification struct {
	Channel  Channel
	Incident Incident
	Actor    dto.ActorSummary
}

type digestItem struct {
	IncidentID string
	Headline   string
	Timestamp  time.Time
}

// Config holds webhook URLs, clients, and narrator dependencies.
type Config struct {
	DiscordURL     string
	SlackURL       string
	DashboardURL   string
	Client         *http.Client
	Narrator       *narrate.Narrator
	Store          *store.Store
	InitialBackoff time.Duration
	DigestInterval time.Duration
	Now            func() time.Time
}

// Notifier dispatches alerts to Discord and Slack with retries and narrative generation.
type Notifier struct {
	cfg         Config
	queue       chan Notification
	digestMu    sync.Mutex
	digestQueue []digestItem
}

// NewNotifier creates an alert notifier with buffered queue.
func NewNotifier(cfg Config) *Notifier {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 500 * time.Millisecond
	}
	if cfg.DigestInterval <= 0 {
		cfg.DigestInterval = DigestInterval
	}
	if cfg.DashboardURL == "" {
		cfg.DashboardURL = "http://localhost:3000"
	}
	return &Notifier{
		cfg:   cfg,
		queue: make(chan Notification, 1000),
	}
}

func (n *Notifier) now() time.Time {
	if n.cfg.Now != nil {
		return n.cfg.Now()
	}
	return time.Now()
}

// Notify enqueues a notification without blocking the caller (returns nil immediately).
func (n *Notifier) Notify(ctx context.Context, ch Channel, inc Incident, actor dto.ActorSummary) error {
	if ch == None {
		return nil
	}
	slog.Info("incident notification", "incident", inc.IncidentID, "severity", inc.Severity, "channel", ch)
	item := Notification{
		Channel:  ch,
		Incident: inc,
		Actor:    actor,
	}
	select {
	case n.queue <- item:
	default:
		slog.Warn("alert queue full, dropping notification", "incident", inc.IncidentID)
	}
	return nil
}

// Run processes the notification queue and periodic digest in the background until ctx is cancelled.
func (n *Notifier) Run(ctx context.Context) {
	ticker := time.NewTicker(n.cfg.DigestInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := n.FlushDigest(ctx); err != nil {
				slog.Error("failed to flush medium alert digest", "err", err)
			}
		case item, ok := <-n.queue:
			if !ok {
				return
			}
			if err := n.DispatchSync(ctx, item.Channel, item.Incident, item.Actor); err != nil {
				slog.Error("failed to dispatch notification", "incident", item.Incident.IncidentID, "err", err)
			}
		}
	}
}

// DispatchSync processes and sends a single notification synchronously.
func (n *Notifier) DispatchSync(ctx context.Context, ch Channel, inc Incident, actor dto.ActorSummary) error {
	if ch == None {
		return nil
	}

	facts, attacker := n.buildFacts(ctx, inc, actor)

	var nar narrate.Narrative
	if n.cfg.Narrator != nil {
		nar = n.cfg.Narrator.Narrate(ctx, "alert", inc.IncidentID, facts, attacker, 3*time.Second)
	} else {
		nar = narrate.Template(facts)
	}

	nar.Headline = StripMentions(nar.Headline)
	nar.Text = StripMentions(nar.Text)
	for i := range nar.Bullets {
		nar.Bullets[i] = StripMentions(nar.Bullets[i])
	}

	if n.cfg.Store != nil {
		fHash := factsHash(facts)
		_ = n.cfg.Store.SaveNarration(ctx, "alert", inc.IncidentID, fHash, nar.Headline, nar.Text, nar.Bullets, nar.Source, nar.Model)
		_ = n.cfg.Store.SetIncidentSummary(ctx, inc.IncidentID, nar.Text, nar.Source)
	}

	if ch == Digest {
		n.digestMu.Lock()
		n.digestQueue = append(n.digestQueue, digestItem{
			IncidentID: inc.IncidentID,
			Headline:   nar.Headline,
			Timestamp:  n.now(),
		})
		n.digestMu.Unlock()
		return nil
	}

	var errs []error
	if n.cfg.DiscordURL != "" {
		payload := n.buildDiscordPayload(inc, actor, nar, facts)
		if err := n.sendWithRetry(ctx, "discord", n.cfg.DiscordURL, payload); err != nil {
			errs = append(errs, fmt.Errorf("discord: %w", err))
		}
	}

	if ch == ImmediateAll && n.cfg.SlackURL != "" {
		payload := n.buildSlackPayload(inc, actor, nar, facts)
		if err := n.sendWithRetry(ctx, "slack", n.cfg.SlackURL, payload); err != nil {
			errs = append(errs, fmt.Errorf("slack: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("dispatch errors: %v", errs)
	}
	return nil
}

// FlushDigest sends any queued medium incident notifications to Discord as a single digest.
func (n *Notifier) FlushDigest(ctx context.Context) error {
	n.digestMu.Lock()
	if len(n.digestQueue) == 0 {
		n.digestMu.Unlock()
		return nil
	}
	items := n.digestQueue
	n.digestQueue = nil
	n.digestMu.Unlock()

	if n.cfg.DiscordURL == "" {
		return nil
	}

	payload := n.buildDigestPayload(items)
	return n.sendWithRetry(ctx, "discord-digest", n.cfg.DiscordURL, payload)
}

func (n *Notifier) buildFacts(ctx context.Context, inc Incident, actor dto.ActorSummary) (narrate.Facts, []string) {
	f := narrate.Facts{
		ActorLabel:   actor.Label,
		Severity:     inc.Severity,
		Risk:         inc.RiskScore,
		Behaviour:    actor.BehaviourClass,
		Services:     actor.Services,
		IPs:          actor.IPs,
		DashboardURL: n.cfg.DashboardURL + "/incidents/" + inc.IncidentID,
	}
	if f.ActorLabel == "" {
		f.ActorLabel = inc.ActorLabel
	}
	if f.Severity == "" {
		f.Severity = "medium"
	}

	var attackerStrings []string
	if n.cfg.Store != nil {
		a, err := n.cfg.Store.Actor(ctx, inc.ActorID)
		if err == nil {
			f.TouchedProduction = a.TouchedProduction
			f.FirstSeen = a.FirstSeen
			f.LastSeen = a.LastSeen
			if f.Behaviour == "" {
				f.Behaviour = a.BehaviourClass
			}
		}
		findings, _ := n.cfg.Store.FindingsOfActor(ctx, inc.ActorID)
		for _, finding := range findings {
			tech := ""
			if finding.Technique != nil {
				tech = *finding.Technique
			}
			f.Findings = append(f.Findings, narrate.Finding{
				Title:     finding.Title,
				Technique: tech,
				TS:        finding.TS,
			})
		}
		sessions, _ := n.cfg.Store.SessionsOfActor(ctx, inc.ActorID)
		iocs, _ := n.cfg.Store.IOCs(ctx, inc.ActorID)
		var tokens []string
		for _, ioc := range iocs {
			if ioc.Kind == "token" {
				tokens = append(tokens, ioc.Value)
			}
		}
		f.Tokens = tokens
		f.Recommended = recommendActions(findings, actor, tokens, sessions)
	}
	return f, attackerStrings
}

func recommendActions(findings []store.FindingRow, sum dto.ActorSummary, tokensUsed []string, sessions []store.SessionRow) []string {
	var out []string
	has := map[string]bool{}
	for _, f := range findings {
		has[f.RuleID] = true
	}
	for _, ip := range sum.IPs {
		if len(has) > 0 {
			out = append(out, "block_ip "+ip)
		}
	}
	for _, t := range tokensUsed {
		out = append(out, "rotate_token "+t)
	}
	if has["ssh_persistence"] || has["cron_persistence"] {
		for _, se := range sessions {
			if se.EndedAt == nil && se.Service == "ssh" {
				out = append(out, "kill_session "+se.SensorSessionID)
			}
		}
	}
	return out
}

func factsHash(f narrate.Facts) string {
	b, _ := json.Marshal(f)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Mention sanitization helpers.
var (
	reDiscordMention = regexp.MustCompile(`(?i)<@[!&]?[0-9a-zA-Z_-]+>`)
	reSlackMention   = regexp.MustCompile(`(?i)<![0-9a-zA-Z^_-]+>`)
	reAtEveryoneHere = regexp.MustCompile(`(?i)@+(everyone|here|channel)`)
	reGenericAt      = regexp.MustCompile(`(?i)(^|\s)@([a-zA-Z0-9_-]+)`)
)

// StripMentions removes or defangs any @everyone, @here, <@...>, <!...> mentions.
func StripMentions(s string) string {
	s = reDiscordMention.ReplaceAllString(s, "")
	s = reSlackMention.ReplaceAllString(s, "")
	s = reAtEveryoneHere.ReplaceAllString(s, "$1")
	s = reGenericAt.ReplaceAllString(s, "$1$2")
	return strings.TrimSpace(s)
}

func footerText(nar narrate.Narrative) string {
	source := "template"
	if nar.Source == "llm" && nar.Model != nil && *nar.Model != "" {
		source = fmt.Sprintf("AI (%s)", *nar.Model)
	}
	return fmt.Sprintf("Deception SOC · lab environment · text: %s", source)
}

func formatDescription(nar narrate.Narrative) string {
	desc := nar.Text
	if len(nar.Bullets) > 0 {
		var bullets []string
		for _, b := range nar.Bullets {
			b = strings.TrimSpace(b)
			if b != "" {
				bullets = append(bullets, "• "+b)
			}
		}
		if len(bullets) > 0 {
			if desc != "" {
				desc += "\n" + strings.Join(bullets, "\n")
			} else {
				desc = strings.Join(bullets, "\n")
			}
		}
	}
	return desc
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// Discord payload models (09 §Discord payload).
type discordPayload struct {
	Content string         `json:"content,omitempty"`
	Embeds  []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	URL         string         `json:"url"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Footer      discordFooter  `json:"footer"`
	Timestamp   string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (n *Notifier) buildDiscordPayload(inc Incident, actor dto.ActorSummary, nar narrate.Narrative, facts narrate.Facts) discordPayload {
	title := fmt.Sprintf("%s — %s", strings.ToUpper(inc.Severity), nar.Headline)
	desc := formatDescription(nar)

	var fields []discordField
	fields = append(fields, discordField{Name: "Risk", Value: fmt.Sprintf("%d / 100", inc.RiskScore), Inline: true})

	beh := actor.BehaviourClass
	if beh == "" {
		beh = "unknown"
	}
	fields = append(fields, discordField{Name: "Behaviour", Value: beh, Inline: true})

	serv := strings.Join(actor.Services, ", ")
	if serv == "" {
		serv = "none"
	}
	fields = append(fields, discordField{Name: "Services", Value: serv, Inline: true})

	trigger := inc.Title
	if len(facts.Findings) > 0 {
		trigger = facts.Findings[len(facts.Findings)-1].Title
	}
	fields = append(fields, discordField{Name: "Trigger", Value: StripMentions(trigger)})

	var recent []string
	for i := len(facts.Findings) - 1; i >= 0 && len(recent) < 5; i-- {
		recent = append(recent, "• "+StripMentions(facts.Findings[i].Title))
	}
	if len(recent) == 0 {
		recent = append(recent, "• "+StripMentions(inc.Title))
	}
	fields = append(fields, discordField{Name: "Recent activity", Value: strings.Join(recent, "\n")})

	seenTech := map[string]bool{}
	var techs []string
	for _, f := range facts.Findings {
		if f.Technique != "" && !seenTech[f.Technique] {
			seenTech[f.Technique] = true
			techs = append(techs, f.Technique)
		}
	}
	attackVal := "none"
	if len(techs) > 0 {
		sort.Strings(techs)
		attackVal = strings.Join(techs, ", ")
	}
	fields = append(fields, discordField{Name: "ATT&CK", Value: attackVal})

	payload := discordPayload{
		Embeds: []discordEmbed{{
			Title:       title,
			Description: desc,
			URL:         n.cfg.DashboardURL + "/incidents/" + inc.IncidentID,
			Color:       Colour(inc.Severity),
			Fields:      fields,
			Footer:      discordFooter{Text: footerText(nar)},
			Timestamp:   n.now().UTC().Format(time.RFC3339),
		}},
	}
	if inc.Severity == "critical" {
		payload.Content = "@here"
	}
	return payload
}

func (n *Notifier) buildDigestPayload(items []digestItem) discordPayload {
	var lines []string
	for _, item := range items {
		line := fmt.Sprintf("• [%s](%s/incidents/%s): %s", item.IncidentID, n.cfg.DashboardURL, item.IncidentID, item.Headline)
		lines = append(lines, line)
	}
	desc := strings.Join(lines, "\n")
	return discordPayload{
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("MEDIUM DIGEST — %d new incidents", len(items)),
			Description: desc,
			Color:       Colour("medium"),
			Footer:      discordFooter{Text: "Deception SOC · lab environment · 15-minute digest"},
			Timestamp:   n.now().UTC().Format(time.RFC3339),
		}},
	}
}

// Slack Block Kit models (09 §Slack payload).
type slackPayload struct {
	Text   string       `json:"text,omitempty"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Fields   []slackText `json:"fields,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

func (n *Notifier) buildSlackPayload(inc Incident, actor dto.ActorSummary, nar narrate.Narrative, facts narrate.Facts) slackPayload {
	title := fmt.Sprintf("%s — %s", strings.ToUpper(inc.Severity), nar.Headline)
	desc := formatDescription(nar)

	var blocks []slackBlock
	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: truncate(title, 150), Emoji: true},
	})
	blocks = append(blocks, slackBlock{
		Type: "section",
		Text: &slackText{Type: "mrkdwn", Text: desc},
	})

	beh := actor.BehaviourClass
	if beh == "" {
		beh = "unknown"
	}
	serv := strings.Join(actor.Services, ", ")
	if serv == "" {
		serv = "none"
	}
	seenTech := map[string]bool{}
	var techs []string
	for _, f := range facts.Findings {
		if f.Technique != "" && !seenTech[f.Technique] {
			seenTech[f.Technique] = true
			techs = append(techs, f.Technique)
		}
	}
	attackVal := "none"
	if len(techs) > 0 {
		sort.Strings(techs)
		attackVal = strings.Join(techs, ", ")
	}

	blocks = append(blocks, slackBlock{
		Type: "section",
		Fields: []slackText{
			{Type: "mrkdwn", Text: fmt.Sprintf("*Risk:*\n%d / 100", inc.RiskScore)},
			{Type: "mrkdwn", Text: fmt.Sprintf("*Behaviour:*\n%s", beh)},
			{Type: "mrkdwn", Text: fmt.Sprintf("*Services:*\n%s", serv)},
			{Type: "mrkdwn", Text: fmt.Sprintf("*ATT&CK:*\n%s", attackVal)},
		},
	})

	incidentURL := n.cfg.DashboardURL + "/incidents/" + inc.IncidentID
	blocks = append(blocks, slackBlock{
		Type: "context",
		Elements: []slackText{
			{Type: "mrkdwn", Text: fmt.Sprintf("<%s|View in SOC Dashboard> · %s", incidentURL, footerText(nar))},
		},
	})

	return slackPayload{
		Text:   truncate(title, 150),
		Blocks: blocks,
	}
}

// sendWithRetry posts a payload to a webhook with 3 retries and exponential backoff.
func (n *Notifier) sendWithRetry(ctx context.Context, targetName, webhookURL string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	backoff := n.cfg.InitialBackoff
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}

	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		client := n.cfg.Client
		if client == nil {
			client = &http.Client{Timeout: 10 * time.Second}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			slog.Warn("webhook delivery attempt failed (network)", "target", targetName, "attempt", attempt+1, "err", err)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		slog.Warn("webhook delivery attempt failed (http)", "target", targetName, "attempt", attempt+1, "status", resp.StatusCode)

		// Don't retry non-429 4xx client errors (bad request etc.)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return lastErr
		}
	}
	return fmt.Errorf("%s webhook failed after %d retries: %w", targetName, maxRetries, lastErr)
}

