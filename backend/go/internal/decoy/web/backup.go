package web

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/persona"
	"golang.org/x/crypto/ssh"
)

type BackupManager struct {
	mu        sync.RWMutex
	zipBytes  []byte
	schemaLog []byte
	migration []byte
}

func NewBackupManager(seedDir string, p persona.Persona) (*BackupManager, error) {
	bm := &BackupManager{}

	// Check if internal-backup.zip is already present in seedDir
	candidates := []string{
		filepath.Join(seedDir, "out", "internal-backup.zip"),
		filepath.Join(seedDir, "internal-backup.zip"),
		filepath.Join("seed", "out", "internal-backup.zip"),
	}
	for _, cand := range candidates {
		if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
			bm.zipBytes = data
			break
		}
	}

	if len(bm.zipBytes) == 0 {
		// Generate the zip on the fly
		data, err := buildBackupZip(seedDir, p)
		if err != nil {
			return nil, fmt.Errorf("build backup zip: %w", err)
		}
		bm.zipBytes = data
	}

	bm.schemaLog = []byte(`-- Schema backup 2026-10-01
CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(64), email VARCHAR(128));
CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, customer_id INT, total NUMERIC(10,2));
-- Dump completed on 2026-10-01 03:00:01
`)
	bm.migration = []byte(`2026-10-15 09:12:00 [INFO] Migration starting: 0042_add_shipping_zones
2026-10-15 09:13:22 [INFO] Applied 0042_add_shipping_zones in 82s
2026-10-15 09:15:00 [INFO] Migration completed successfully.
`)

	return bm, nil
}

func (bm *BackupManager) ZipData() []byte {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.zipBytes
}

func (bm *BackupManager) SchemaData() []byte {
	return bm.schemaLog
}

func (bm *BackupManager) MigrationLog() []byte {
	return bm.migration
}

func buildBackupZip(seedDir string, p persona.Persona) ([]byte, error) {
	// 1. Get or generate ed25519 private key for deploy
	var privKeyPEM []byte

	// Check if deploy key exists in seed
	keyCandidates := []string{
		filepath.Join(seedDir, "out", "deploy_id_ed25519"),
		filepath.Join(seedDir, "deploy_id_ed25519"),
		filepath.Join("seed", "out", "deploy_id_ed25519"),
	}
	for _, cand := range keyCandidates {
		if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
			privKeyPEM = data
			break
		}
	}

	if len(privKeyPEM) == 0 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate deploy key: %w", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, "deploy@"+p.Hostname)
		if err != nil {
			return nil, fmt.Errorf("marshal deploy key: %w", err)
		}
		privKeyPEM = pem.EncodeToMemory(block)
	}

	// 2. Prepare notes.txt
	notesContent := fmt.Sprintf(`Host: %s (%s)
Port: 2222
User: deploy
Auth: deploy_id_ed25519
Note: Automated migration sync key. Do not share outside deployment engineering.
Last updated: %s
`, p.Hostname, p.Domain, time.Now().Format("2006-01-02"))

	// 3. Assemble zip
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	// Add deploy_id_ed25519
	keyHeader := &zip.FileHeader{
		Name:     "deploy_id_ed25519",
		Method:   zip.Deflate,
		Modified: time.Now(),
	}
	keyHeader.SetMode(0o600)
	keyWriter, err := zw.CreateHeader(keyHeader)
	if err != nil {
		return nil, err
	}
	if _, err := keyWriter.Write(privKeyPEM); err != nil {
		return nil, err
	}

	// Add notes.txt
	notesHeader := &zip.FileHeader{
		Name:     "notes.txt",
		Method:   zip.Deflate,
		Modified: time.Now(),
	}
	notesHeader.SetMode(0o644)
	notesWriter, err := zw.CreateHeader(notesHeader)
	if err != nil {
		return nil, err
	}
	if _, err := notesWriter.Write([]byte(notesContent)); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

