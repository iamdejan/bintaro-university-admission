package database

import (
	"context"
	"database/sql"
	"time"
)

type Session struct {
	SessionToken string
	UserID       string
	expiresAt    string // expiresAt is a string representation of time. It should be formatted according to RFC3339 format.
}

func NewSession(sessionToken string, userID string, expiryTime time.Time) Session {
	return Session{
		SessionToken: sessionToken,
		UserID:       userID,
		expiresAt:    expiryTime.Format(time.RFC3339),
	}
}

func (s Session) ExpiryTime() time.Time {
	t, _ := time.Parse(time.RFC3339, s.expiresAt)
	return t
}

const insertSessionSQLQuery = `
INSERT INTO sessions(
	session_token
	,user_id
	,expires_at
) VALUES (
	$1
	,$2
	,$3
)
`

func InsertSession(ctx context.Context, db *sql.DB, session Session) error {
	_, err := db.ExecContext(
		ctx,
		insertSessionSQLQuery,
		session.SessionToken,
		session.UserID,
		session.expiresAt,
	)
	return err
}

const getSessionSQLQuery = `
SELECT user_id
,expires_at
FROM sessions
WHERE session_token = $1
`

func GetSession(ctx context.Context, db *sql.DB, sessionToken string) (*Session, error) {
	row := db.QueryRowContext(ctx, getSessionSQLQuery, sessionToken)

	var userID string
	var expiresAt string
	if err := row.Scan(&userID, &expiresAt); err != nil {
		return nil, err
	}

	return &Session{
		SessionToken: sessionToken,
		UserID:       userID,
		expiresAt:    expiresAt,
	}, nil
}

const deleteSQLQuery = `
DELETE FROM sessions
WHERE session_token = $1
`

func DeleteSession(ctx context.Context, db *sql.DB, sessionToken string) error {
	_, err := db.ExecContext(ctx, deleteSQLQuery, sessionToken)
	return err
}
