package store

import (
	"context"
	"database/sql"
)

type User struct {
	ID             string
	FullName       string
	Nationality    string
	Email          string
	HashedPassword string
}

type UserStore interface {
	GetByID(ctx context.Context, userID string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Insert(ctx context.Context, user User) error
}

type UserStoreImpl struct {
	db *sql.DB
}

var _ UserStore = (*UserStoreImpl)(nil)

func NewUserStore(db *sql.DB) UserStore {
	return &UserStoreImpl{
		db: db,
	}
}

const getUserByIDSQLQuery = `
SELECT id
,full_name
,nationality
,email
,hashed_password
FROM users
WHERE id = $1
`

func (u *UserStoreImpl) GetByID(ctx context.Context, userID string) (*User, error) {
	row := u.db.QueryRowContext(ctx, getUserByIDSQLQuery, userID)

	var fullName string
	var nationality string
	var email string
	var hashedPassword string
	if err := row.Scan(&userID, &fullName, &nationality, &email, &hashedPassword); err != nil {
		return nil, err
	}

	return &User{
		ID:             userID,
		FullName:       fullName,
		Nationality:    nationality,
		Email:          email,
		HashedPassword: hashedPassword,
	}, nil
}

const getUserByEmailSQLQuery = `
SELECT id
,full_name
,nationality
,email
,hashed_password
FROM users
WHERE email = $1
`

func (u *UserStoreImpl) GetByEmail(ctx context.Context, email string) (*User, error) {
	row := u.db.QueryRowContext(ctx, getUserByEmailSQLQuery, email)
	var userID string
	var fullName string
	var nationality string
	var hashedPassword string

	if err := row.Scan(&userID, &fullName, &nationality, &email, &hashedPassword); err != nil {
		return nil, err
	}

	return &User{
		ID:             userID,
		FullName:       fullName,
		Nationality:    nationality,
		HashedPassword: hashedPassword,
	}, nil
}

const insertUserSQLQuery = `
INSERT INTO users (
	id
	,full_name
	,nationality
	,email
	,hashed_password
) VALUES (
	$1
	,$2
	,$3
	,$4
	,$5
);
`

func (u *UserStoreImpl) Insert(ctx context.Context, user User) error {
	_, err := u.db.ExecContext(
		ctx,
		insertUserSQLQuery,
		user.ID,
		user.FullName,
		user.Nationality,
		user.Email,
		user.HashedPassword,
	)
	return err
}
