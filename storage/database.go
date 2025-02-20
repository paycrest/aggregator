package storage

import (
	"context"
	"database/sql"
	"log"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/migrate"
	_ "github.com/paycrest/aggregator/ent/runtime" // ent runtime

	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	// Client holds the database connection
	Client *ent.Client
	// DB holds the database connection
	DB *sql.DB
	// Err holds database connection error
	Err error
)

// DBConnection create database connection
func DBConnection(DSN string) error {
	log.Println("Connecting to the database with DSN: ", DSN)
	var db *sql.DB
	var err error
	for i := 0; i < 3; i++ { // Retry mechanism
		db, err = sql.Open("pgx", DSN)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second) // Wait before retrying
	}

	if err != nil {
		Err = err
		log.Println("Database connection error")
		return err
	}

	log.Println("Connecting to the database successful")

	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(100)
	db.SetConnMaxLifetime(2 * time.Minute)

	DB = db

	log.Println("DB connection config")
	// Create an ent.Driver from `db`.
	drv := entsql.OpenDB(dialect.Postgres, db)

	// Integrate sql.DB to ent.Client.
	client := ent.NewClient(ent.Driver(drv))

	conf := config.ServerConfig()

	log.Println("Running migration")	
	// Run the auto migration tool.
	if conf.Environment == "local" {
		if err := client.Schema.Create(context.Background(), migrate.WithGlobalUniqueID(true)); err != nil {
			log.Println("err", err)
			return err
		}
	}

	Client = client

	log.Println("DB connection done")

	return nil
}

// GetClient connection
func GetClient() *ent.Client {
	return Client
}

// GetError connection error
func GetError() error {
	return Err
}
