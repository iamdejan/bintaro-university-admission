package store

import (
	"context"
	"database/sql"
	"time"
)

type CSRFToken struct {
	Token     string
	expiresAt string
}

func (t *CSRFToken) ExpiryTime() time.Time {
	parsedTime, _ := time.Parse(time.RFC3339, t.expiresAt)
	return parsedTime
}

func (t *CSRFToken) IsExpired() bool {
	return time.Now().After(t.ExpiryTime())
}

func NewCSRFToken(token string, expiresAt time.Time) CSRFToken {
	return CSRFToken{
		Token:     token,
		expiresAt: expiresAt.Format(time.RFC3339),
	}
}

type CSRFTokenStore interface {
	Insert(ctx context.Context, token CSRFToken) error
	Get(ctx context.Context, tokenValue string) (*CSRFToken, error)
	Delete(ctx context.Context, tokenValue string) error
}

type CSRFTokenStoreImpl struct {
	db *sql.DB
}

var _ CSRFTokenStore = (*CSRFTokenStoreImpl)(nil)

func NewCSRFTokenStore(db *sql.DB) CSRFTokenStore {
	return &CSRFTokenStoreImpl{
		db: db,
	}
}

func (c *CSRFTokenStoreImpl) Insert(ctx context.Context, token CSRFToken) error {
	// TODO dejan
	panic("unimplemented")
}

func (c *CSRFTokenStoreImpl) Get(ctx context.Context, tokenValue string) (*CSRFToken, error) {
	// TODO dejan
	panic("unimplemented")
}

func (c *CSRFTokenStoreImpl) Delete(ctx context.Context, tokenValue string) error {
	// TODO dejan
	panic("unimplemented")
}
