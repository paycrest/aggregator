//go:build ignore

package main

import (
	"context"
	"log"
	"os"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"

	atlas "ariga.io/atlas/sql/migrate"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"
	_ "github.com/lib/pq"
)

func main() {
	ctx := context.Background()
	// Create a local migration directory able to understand Atlas migration file format for replay.
	dir, err := atlas.NewLocalDir("ent/migrate/migrations")
	if err != nil {
		log.Fatalf("failed creating atlas migration directory: %v", err)
	}
	// Migrate diff options.
	opts := []schema.MigrateOption{
		schema.WithDir(dir),                         // provide migration directory
		schema.WithMigrationMode(schema.ModeReplay), // provide migration mode
		schema.WithDialect(dialect.Postgres),        // Ent dialect to use
		schema.WithFormatter(atlas.DefaultFormatter),
		schema.WithGlobalUniqueID(true),
		schema.WithDropIndex(true),
		schema.WithDropColumn(true),
	}
	if len(os.Args) != 2 {
		log.Fatalln("migration name is required. Use: 'go run -mod=mod ent/migrate/main.go <name>'")
	}

	// Generate migrations using Atlas support for Postgres (note the Ent dialect option passed above).
	client, err := ent.Open(dialect.Postgres, config.DBConfig())
	if err != nil {
		log.Fatalf("database connection error: %v", err)
	}
	defer client.Close()

	if err := client.Schema.Create(ctx, opts...); err != nil {
		log.Fatalf("failed generating migration file: %v", err)
	}
}
