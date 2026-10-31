// Command reset-demo wipes recorded activity from the SOC database for a clean demo, keeping the setup.
//
//	reset-demo            dry run: show what would be deleted, change nothing
//	reset-demo -yes       delete it (asks nothing more; there is no undo)
//
// Deleted: events, sessions, actors, fingerprints, findings, token hits, incidents (+ notes, actions, feedback),
// maze state, deception tactics, generated lures, narrations, recovery plans, and every policy row (blocks, kills,
// diversions, releases, burned tokens). Actor labels restart at ACT-0001 and burned honeytokens are reactivated.
// Kept: users, sensors, honeytokens (same values as the planted lures), allowlist, scorer weights.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ryuma04/decoy/backend/internal/store"
)

// Children first, so foreign keys never block a delete.
var wipe = []string{
	"recovery_plans", "narrations", "deception_tactics", "generated_lures", "risk_feedback", "maze_state",
	"response_actions", "incident_notes", "incidents", "findings", "token_hits", "fingerprints", "events",
	"sessions", "actors", "policy",
}

var keep = []string{"users", "sensors", "honeytokens", "allowlist", "scorer_weights"}

func main() {
	yes := flag.Bool("yes", false, "really delete (without it this is a dry run)")
	flag.Parse()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		fail("DATABASE_URL is not set (load .env first)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := store.Open(ctx, url)
	if err != nil {
		fail("open database: " + err.Error())
	}
	defer st.Close()

	fmt.Printf("database: %s\n\n", redact(url))
	fmt.Println("will DELETE all rows in:")
	total := 0
	for _, t := range wipe {
		n := count(ctx, st, t)
		total += n
		fmt.Printf("  %-18s %8d\n", t, n)
	}
	fmt.Println("will KEEP:")
	for _, t := range keep {
		fmt.Printf("  %-18s %8d\n", t, count(ctx, st, t))
	}
	if !*yes {
		fmt.Printf("\ndry run: nothing changed (%d rows would be deleted). Re-run with -yes to delete.\n", total)
		return
	}

	err = st.Tx(ctx, func(tx pgx.Tx) error {
		for _, t := range wipe {
			if _, err := tx.Exec(ctx, "DELETE FROM "+t); err != nil {
				return fmt.Errorf("%s: %w", t, err)
			}
		}
		if _, err := tx.Exec(ctx, "ALTER SEQUENCE actor_label_seq RESTART WITH 1"); err != nil {
			return fmt.Errorf("actor_label_seq: %w", err)
		}
		_, err := tx.Exec(ctx, "UPDATE honeytokens SET burned = false WHERE burned")
		return err
	})
	if err != nil {
		fail("reset failed, nothing was deleted: " + err.Error())
	}
	fmt.Printf("\ndeleted %d rows; actor labels restart at ACT-0001; honeytokens active.\n", total)
	fmt.Println("Restart core (scripts/dev-down.sh && scripts/dev-up.sh) so its in-memory state starts clean too.")
}

func count(ctx context.Context, st *store.Store, table string) int {
	var n int
	if err := st.Pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		fail(table + ": " + err.Error())
	}
	return n
}

// redact hides the password in a postgres URL.
func redact(u string) string {
	at := strings.LastIndex(u, "@")
	scheme := strings.Index(u, "://")
	if at < 0 || scheme < 0 {
		return u
	}
	creds := u[scheme+3 : at]
	if user, _, ok := strings.Cut(creds, ":"); ok {
		return u[:scheme+3] + user + ":***" + u[at:]
	}
	return u
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "reset-demo: "+msg)
	os.Exit(1)
}
