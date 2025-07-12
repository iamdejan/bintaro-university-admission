package database

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

const getUserByIDSQLQuery = `
SELECT id
,full_name
,nationality
,email
,hashed_password
FROM users
WHERE id = $1
`

func GetUserByID(ctx context.Context, db *sql.DB, userID string) (*User, error) {
	row := db.QueryRowContext(ctx, getUserByIDSQLQuery, userID)

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

func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (*User, error) {
	row := db.QueryRowContext(ctx, getUserByEmailSQLQuery, email)
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

func InsertUser(ctx context.Context, db *sql.DB, user User) error {
	_, err := db.ExecContext(
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
