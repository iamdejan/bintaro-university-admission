package router

import (
	"database/sql"
	"log"
	"net/http"

	"bintaro-university-admission/internal/pages"
	"bintaro-university-admission/internal/utils"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const sessionToken = "session_token"

func auth(r chi.Router, db *sql.DB) {
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		login := pages.Login()
		templ.Handler(login).ServeHTTP(w, r)
	})

	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Fatal("Fail to parse form:", err)
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		getPasswordSQLQuery := `
			SELECT password
			FROM users
			WHERE email = $1
		`
		row := db.QueryRowContext(r.Context(), getPasswordSQLQuery, email)
		var expectedPassword string
		if err := row.Scan(&expectedPassword); err != nil {
			log.Fatal("User not found", err)
		}

		if err := utils.ValidatePassword(expectedPassword, password); err != nil {
			log.Fatal("Wrong password", err)
		}

		cookie := http.Cookie{
			Name:     sessionToken,
			Value:    utils.GenerateRandomString(20),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, &cookie)

		http.Redirect(w, r, "/dashboard", http.StatusMovedPermanently)
	})

	r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		register := pages.Register()
		templ.Handler(register).ServeHTTP(w, r)
	})

	r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Fatal("Fail to parse form:", err)
		}

		fullName := r.FormValue("fullName")
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirmPassword")
		nationality := r.FormValue("nationality")
		id := uuid.NewString()

		if password != confirmPassword {
			log.Fatal("password is not confirmed")
		}

		hashedPassword, hashedPasswordErr := utils.HashPassword(password)
		if hashedPasswordErr != nil {
			log.Fatal("Fail to hash password:", hashedPasswordErr)
		}

		insertSQLQuery := `
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
		_, err := db.ExecContext(r.Context(), insertSQLQuery, id, fullName, nationality, email, hashedPassword)
		if err != nil {
			log.Fatal("Fail to register account:", err)
		}

		http.Redirect(w, r, "/dashboard", http.StatusMovedPermanently)
	})

	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/login", http.StatusMovedPermanently)
	})
}
