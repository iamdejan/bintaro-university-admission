package database

import (
	"context"
	"database/sql"
)

type GetUserResponse struct {
	ID               string
	Email            string
	ExpectedPassword string
}

const getPasswordSQLQuery = `
	SELECT id
	,password
	FROM users
	WHERE email = $1
`

func GetUser(ctx context.Context, db *sql.DB, email string) (*GetUserResponse, error) {

	row := db.QueryRowContext(ctx, getPasswordSQLQuery, email)
	var userID string
	var expectedPassword string

	if err := row.Scan(&userID, &expectedPassword); err != nil {
		return nil, err
	}

	return &GetUserResponse{
		ID:               userID,
		Email:            email,
		ExpectedPassword: expectedPassword,
	}, nil
}

type CreateUserRequest struct {
	ID             string
	FullName       string
	Nationality    string
	Email          string
	HashedPassword string
}

const insertSQLQuery = `
	INSERT INTO users (
		id
		,full_name
		,nationality
		,email
		,password
	) VALUES (
		$1
		,$2
		,$3
		,$4
		,$5
	);
	`

func InsertUser(ctx context.Context, db *sql.DB, user CreateUserRequest) error {
	_, err := db.ExecContext(ctx, insertSQLQuery, user.ID, user.FullName, user.Nationality, user.Email, user.HashedPassword)
	return err
}
