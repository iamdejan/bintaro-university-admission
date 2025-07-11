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
	_, err := db.ExecContext(ctx, insertSessionSQLQuery, session.ID, session.UserID, session.SessionToken, session.ExpiresAt)
	return err
}
