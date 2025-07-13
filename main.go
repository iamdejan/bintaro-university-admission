package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"bintaro-university-admission/internal/router"
	"bintaro-university-admission/internal/store"

	_ "github.com/mattn/go-sqlite3"
)

const initiateTablesSQLQuery = `
CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY,
	full_name VARCHAR(255),
	nationality CHAR(3),
	email VARCHAR(255) UNIQUE,
	hashed_password VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS sessions (
	session_token VARCHAR(255) PRIMARY KEY,
	user_id UUID,
	type TEXT CHECK(type IN ('GENERAL', 'OTP')),
	expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS multi_factor_auth (
	id UUID PRIMARY KEY,
	user_id UUID,
	secret_base32 CHAR(32)
);

CREATE INDEX IF NOT EXISTS multi_factor_auth_user_id ON multi_factor_auth (user_id);
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

	userStore := store.NewUserStore(db)
	sessionStore := store.NewSessionStore(db)
	mfaStore := store.NewMultiFactorAuthStore(db)

	hg := router.NewHandlerGroup(userStore, sessionStore, mfaStore)
	mg := router.NewMiddlewareGroup(userStore, sessionStore)
	r := router.NewRouter(hg, mg)
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
