// Package migrations embeds the SQL migrations (03-database) so core applies them on start-up.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
