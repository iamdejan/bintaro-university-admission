package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type SessionType int

const (
	SessionTypeUnknown SessionType = iota
	SessionTypeGeneral
	SessionTypeOTP
)

func (st SessionType) String() string {
	switch st {
	case SessionTypeGeneral:
		return "GENERAL"
	case SessionTypeOTP:
		return "OTP"
	default:
		return ""
	}
}

func SessionTypeFromString(s string) (SessionType, error) {
	switch s {
	case "GENERAL":
		return SessionTypeGeneral, nil
	case "OTP":
		return SessionTypeOTP, nil
	default:
		return SessionTypeUnknown, errors.New("unknown enum")
	}
}

type Session struct {
	SessionToken string
	UserID       string
	Type         SessionType
	expiresAt    string // expiresAt is a string representation of time. It should be formatted according to RFC3339 format.
}

func NewSession(
	sessionToken string,
	userID string,
	sessionType SessionType,
	expiryTime time.Time,
) Session {
	return Session{
		SessionToken: sessionToken,
		UserID:       userID,
		Type:         sessionType,
		expiresAt:    expiryTime.Format(time.RFC3339),
	}
}

func (s Session) ExpiryTime() time.Time {
	t, _ := time.Parse(time.RFC3339, s.expiresAt)
	return t
}

type SessionStore interface {
	Insert(ctx context.Context, session Session) error
	Get(ctx context.Context, sessionToken string) (*Session, error)
	Delete(ctx context.Context, sessionToken string) error
}

type SessionStoreImpl struct {
	db *sql.DB
}

var _ SessionStore = (*SessionStoreImpl)(nil)

func NewSessionStore(db *sql.DB) SessionStore {
	return &SessionStoreImpl{
		db: db,
	}
}

const insertSessionSQLQuery = `
INSERT INTO sessions(
	session_token
	,user_id
	,type
	,expires_at
) VALUES (
	$1
	,$2
	,$3
	,$4
)
`

func (s *SessionStoreImpl) Insert(ctx context.Context, session Session) error {
	_, err := s.db.ExecContext(
		ctx,
		insertSessionSQLQuery,
		session.SessionToken,
		session.UserID,
		session.Type.String(),
		session.expiresAt,
	)
	return err
}

const getSessionSQLQuery = `
SELECT user_id
,type
,expires_at
FROM sessions
WHERE session_token = $1
`

func (s *SessionStoreImpl) Get(ctx context.Context, sessionToken string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, getSessionSQLQuery, sessionToken)

	var userID string
	var st string
	var expiresAt string
	if err := row.Scan(&userID, &st, &expiresAt); err != nil {
		return nil, err
	}

	sessionType, err := SessionTypeFromString(st)
	if err != nil {
		return nil, err
	}

	return &Session{
		SessionToken: sessionToken,
		UserID:       userID,
		Type:         sessionType,
		expiresAt:    expiresAt,
	}, nil
}

const deleteSQLQuery = `
DELETE FROM sessions
WHERE session_token = $1
`

func (s *SessionStoreImpl) Delete(ctx context.Context, sessionToken string) error {
	_, err := s.db.ExecContext(ctx, deleteSQLQuery, sessionToken)
	return err
}
