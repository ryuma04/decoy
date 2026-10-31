// Command seed generates the persona and the five honeytokens (06 §5), writes them for the decoys
// (seed/out/persona.json, seed/out/tokens.json) and registers the tokens in the database.
//
// Every token value is random and does not work anywhere: AWS-style key ids never match a real account,
// and passwords / bearer tokens only exist inside our decoys.
//
//	seed                 generate (PERSONA_SEED or random) and insert
//	seed --rotate <id>   replace one token with a fresh value (after the analyst burned it)
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/store"
)

type Token struct {
	TokenID     string `json:"token_id"`
	Kind        string `json:"kind"`
	PlantedAt   string `json:"planted_at"`
	MazeNode    string `json:"maze_node"`
	MatchValue  string `json:"match_value"`
	Sensitivity int    `json:"sensitivity"`
	// File the SSH decoy plants (fakefs) for this token, if any.
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
	Hidden  bool   `json:"hidden,omitempty"`
}

func randString(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[k.Int64()]
	}
	return string(b)
}

const (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	hexdig = "0123456789abcdef"
)

func tokens(p persona.Persona) map[string]Token {
	aws := "AKIA" + randString(upper, 16)
	awsSecret := randString(alnum, 40)
	bearer := randString(alnum, 48)
	dbPass := randString(alnum, 18)
	keyFP := "SHA256:" + randString(alnum, 43) // replaced by the real fingerprint when the deploy key is generated
	return map[string]Token{
		"tok_backup_key": {TokenID: "tok_backup_key", Kind: "ssh_key", PlantedAt: "web:/admin/backup/internal-backup.zip",
			MazeNode: "lure_backup", MatchValue: keyFP, Sensitivity: 4},
		"tok_aws_k7": {TokenID: "tok_aws_k7", Kind: "aws_key", PlantedAt: "ssh:/home/deploy/.aws/credentials", MazeNode: "lure_aws",
			MatchValue: aws, Sensitivity: 5, Path: "/home/deploy/.aws/credentials",
			Content: fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = ap-south-1\n", aws, awsSecret)},
		"tok_kube": {TokenID: "tok_kube", Kind: "kubeconfig", PlantedAt: "ssh:/opt/deploy/kubeconfig", MazeNode: "lure_kubeconfig",
			MatchValue: bearer, Sensitivity: 5, Path: "/opt/deploy/kubeconfig", Hidden: true,
			Content: fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: %s-prod\n  cluster:\n    server: https://k8s.%s:6443\n    insecure-skip-tls-verify: true\nusers:\n- name: deploy-reader\n  user:\n    token: %s\ncontexts:\n- name: prod\n  context: {cluster: %s-prod, user: deploy-reader, namespace: default}\ncurrent-context: prod\n",
				p.HostPrefix, p.Domain, bearer, p.HostPrefix)},
		"tok_db": {TokenID: "tok_db", Kind: "db_cred", PlantedAt: "ssh:/etc/app/db.env", MazeNode: "lure_db",
			MatchValue: dbPass, Sensitivity: 4, Path: "/etc/app/db.env", Hidden: true,
			Content: fmt.Sprintf("DB_HOST=db.%s\nDB_PORT=5432\nDB_USER=app\nDB_PASS=%s\nDB_NAME=orders\n", p.Domain, dbPass)},
		"tok_url": {TokenID: "tok_url", Kind: "url", PlantedAt: "ssh:/home/deploy/.bash_history", MazeNode: "",
			MatchValue: "/t/tok_url", Sensitivity: 2, Path: "/home/deploy/.bash_history",
			Content: fmt.Sprintf("ls -la\ncd /opt/deploy\ncurl -s http://s3.%s:8088/t/tok_url -o status.json\nexit\n", p.Domain)},
	}
}

func main() {
	rotate := flag.String("rotate", "", "token id to replace with a fresh value")
	out := flag.String("out", envOr("SEED_OUT", "seed/out"), "output directory")
	flag.Parse()
	seed := os.Getenv("PERSONA_SEED")
	if seed == "" {
		seed = randString(hexdig, 12)
	}
	p := persona.Load(filepath.Join(*out, "persona.json"), seed)
	toks := tokens(p)
	if *rotate != "" {
		old := map[string]Token{}
		if b, err := os.ReadFile(filepath.Join(*out, "tokens.json")); err == nil {
			_ = json.Unmarshal(b, &old)
		}
		fresh, ok := toks[*rotate]
		if !ok {
			fail("unknown token id " + *rotate)
		}
		old[*rotate] = fresh
		toks = old
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err.Error())
	}
	write(filepath.Join(*out, "persona.json"), p)
	write(filepath.Join(*out, "tokens.json"), toks)

	if url := os.Getenv("DATABASE_URL"); url != "" {
		ctx := context.Background()
		if err := store.Migrate(url); err != nil {
			fail(err.Error())
		}
		st, err := store.Open(ctx, url)
		if err != nil {
			fail(err.Error())
		}
		defer st.Close()
		for _, t := range toks {
			node := &t.MazeNode
			if t.MazeNode == "" {
				node = nil
			}
			if err := st.UpsertHoneytoken(ctx, store.Honeytoken{TokenID: t.TokenID, Kind: t.Kind, PlantedAt: t.PlantedAt,
				MazeNode: node, MatchValue: t.MatchValue, Sensitivity: t.Sensitivity}); err != nil {
				fail(err.Error())
			}
		}
		slog.Info("honeytokens registered", "count", len(toks))
	}
	slog.Info("seed written", "dir", *out, "company", p.Company, "host", p.Hostname)
}

func write(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fail(err.Error())
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fail(msg string) {
	slog.Error("seed failed", "err", msg)
	os.Exit(1)
}
