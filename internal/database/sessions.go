package database

import (
	"context"
	"database/sql"
	"time"
)

type Session struct {
	ID           string
	UserID       string
	SessionToken string
	ExpiresAt    time.Time
}

const insertSessionSQLQuery = `
INSERT INTO sessions(
	id
	,user_id
	,session_token
	,expires_at
) VALUES (
	$1
	,$2
	,$3
	,$4 
)
`

func InsertSession(ctx context.Context, db *sql.DB, session Session) error {
	_, err := db.ExecContext(
		ctx,
		insertSessionSQLQuery,
		session.ID,
		session.UserID,
		session.SessionToken,
		session.ExpiresAt,
	)
	return err
}

const deleteSQLQuery = `
DELETE FROM sessions
WHERE session_token = $1
`

func DeleteSession(ctx context.Context, db *sql.DB, sessionToken string) error {
	_, err := db.ExecContext(ctx, deleteSQLQuery, sessionToken)
	return err
}
