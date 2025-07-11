package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"bintaro-university-admission/internal/router"

	_ "github.com/mattn/go-sqlite3"
)

const initiateTablesSQLQuery = `
CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY,
	full_name VARCHAR(255),
	nationality CHAR(3),
	email VARCHAR(255) UNIQUE,
	password VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS sessions (
	id UUID PRIMARY KEY,
	user_id UUID,
	session_token VARCHAR(255) UNIQUE,
	expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS multi_factor_auth (
	id UUID PRIMARY KEY,
	slug varchar(255) UNIQUE,
	user_id UUID,
	secret_base32 CHAR(26)
);
`

func main() {
	ctx := context.Background()

	// database setup
	db, err := sql.Open("sqlite3", "./database.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	_, err = db.ExecContext(ctx, initiateTablesSQLQuery)
	if err != nil {
		panic(err)
	}

	r := router.NewRouter(db)
	server := http.Server{
		Handler:      r,
		Addr:         ":9000",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	log.Print("Running server at ", server.Addr)
	if err = server.ListenAndServe(); err != nil {
		panic(err)
	}
}
