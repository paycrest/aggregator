package storage

import (
	"context"
	"database/sql"
	"log"
	"time"
	"fmt"
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
		fmt.Println("DB CONNECT ERR 1", err)
		Err = err
		log.Println("Database connection error")
		return err
	}

	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(100)
	db.SetConnMaxLifetime(2 * time.Minute)

	DB = db

	// Create an ent.Driver from `db`.
	drv := entsql.OpenDB(dialect.Postgres, db)

	// Integrate sql.DB to ent.Client.
	client := ent.NewClient(ent.Driver(drv))

	conf := config.ServerConfig()

	// Run the auto migration tool.
	if conf.Environment == "local" {
		if err := client.Schema.Create(context.Background(), migrate.WithGlobalUniqueID(true)); err != nil {
			fmt.Println("DB CONNECT ERR 2", err)
			return err
		}
	}

	Client = client

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
