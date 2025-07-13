package store

import (
	"context"
	"database/sql"

	"bintaro-university-admission/internal/random"

	"github.com/google/uuid"
)

const secretLength = 32

type MultiFactorAuth struct {
	ID           string
	Slug         string
	UserID       string
	SecretBase32 string
}

func NewMultiFactorAuth(userID string, slug string) MultiFactorAuth {
	secretBase32, _ := random.GenerateBase32(secretLength)

	return MultiFactorAuth{
		ID:           uuid.NewString(),
		Slug:         slug,
		UserID:       userID,
		SecretBase32: secretBase32,
	}
}

type MultiFactorAuthStore interface {
	Insert(ctx context.Context, mfa MultiFactorAuth) error
	GetBySlug(ctx context.Context, slug string) (*MultiFactorAuth, error)
	GetSlugsByUserID(ctx context.Context, userID string) ([]string, error)
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
	,slug
	,user_id
	,secret_base32
) VALUES (
$1
,$2
,$3
,$4 
);
`

func (m *MultiFactorAuthStoreImpl) Insert(ctx context.Context, mfa MultiFactorAuth) error {
	_, err := m.db.ExecContext(ctx, insertMFASQLQuery, mfa.ID, mfa.Slug, mfa.UserID, mfa.SecretBase32)
	return err
}

const getMFABySlugSQLQuery = `
SELECT
id
,slug
,user_id
,secret_base32
FROM multi_factor_auth
WHERE slug = $1
`

func (m *MultiFactorAuthStoreImpl) GetBySlug(ctx context.Context, slug string) (*MultiFactorAuth, error) {
	row := m.db.QueryRowContext(ctx, getMFABySlugSQLQuery, slug)

	var id, userID, secretBase32 string
	if err := row.Scan(&id, &slug, &userID, &secretBase32); err != nil {
		return nil, err
	}

	return &MultiFactorAuth{
		ID:           id,
		UserID:       userID,
		Slug:         slug,
		SecretBase32: secretBase32,
	}, nil
}

const getMFASlugsByUserIDSQLQuery = `
SELECT slug
FROM multi_factor_auth
WHERE user_id = $1
`

func (m *MultiFactorAuthStoreImpl) GetSlugsByUserID(ctx context.Context, userID string) ([]string, error) {
	rows, err := m.db.QueryContext(ctx, getMFASlugsByUserIDSQLQuery, userID)
	if err != nil {
		return nil, err
	}

	mfas := make([]string, 0)
	for rows.Next() {
		var slug string
		if err = rows.Scan(&slug); err != nil {
			return nil, err
		}

		mfas = append(mfas, slug)
	}

	return mfas, nil
}
