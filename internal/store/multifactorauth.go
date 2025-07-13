package store

import (
	"context"
	"database/sql"
)

type MultiFactorAuth struct {
	ID           string
	UserID       string
	SecretBase32 string
}

type MultiFactorAuthStore interface {
	Insert(ctx context.Context, mfa MultiFactorAuth) error
	GetByUserID(ctx context.Context, userID string) (*MultiFactorAuth, error)
	DeleteByUserID(ctx context.Context, userID string) error
}

type MultiFactorAuthStoreImpl struct {
	db *sql.DB
}

var _ MultiFactorAuthStore = (*MultiFactorAuthStoreImpl)(nil)

func NewMultiFactorAuthStore(db *sql.DB) MultiFactorAuthStore {
	return &MultiFactorAuthStoreImpl{
		db: db,
	}
}

const insertMFASQLQuery = `
INSERT INTO multi_factor_auth (
	id
	,user_id
	,secret_base32
) VALUES (
$1
,$2
,$3
);
`

func (m *MultiFactorAuthStoreImpl) Insert(ctx context.Context, mfa MultiFactorAuth) error {
	_, err := m.db.ExecContext(ctx, insertMFASQLQuery, mfa.ID, mfa.UserID, mfa.SecretBase32)
	return err
}

const getMFAByUserIDSQLQuery = `
SELECT
id
,user_id
,secret_base32
FROM multi_factor_auth
WHERE user_id = $1
`

func (m *MultiFactorAuthStoreImpl) GetByUserID(
	ctx context.Context,
	userID string,
) (*MultiFactorAuth, error) {
	row := m.db.QueryRowContext(ctx, getMFAByUserIDSQLQuery, userID)

	var id, secretBase32 string
	if err := row.Scan(&id, &userID, &secretBase32); err != nil {
		return nil, err
	}

	return &MultiFactorAuth{
		ID:           id,
		UserID:       userID,
		SecretBase32: secretBase32,
	}, nil
}

const deleteMFAByUserIDSQLQuery = `
DELETE
FROM multi_factor_auth
WHERE user_id = $1
`

func (m *MultiFactorAuthStoreImpl) DeleteByUserID(ctx context.Context, userID string) error {
	_, err := m.db.ExecContext(ctx, deleteMFAByUserIDSQLQuery, userID)
	return err
}
