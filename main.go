package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"bintaro-university-admission/pages"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

//nolint:funlen
func main() {
	ctx := context.Background()

	// database setup
	db, err := sql.Open("sqlite3", "./database.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	{
		sqlStmt := `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY,
			full_name VARCHAR(255),
			nationality CHAR(3),
			email VARCHAR(255),
			password VARCHAR(255)
		);

		CREATE TABLE IF NOT EXISTS multi_factor_auth (
			id UUID PRIMARY KEY,
			slug varchar(255) UNIQUE,
			user_id UUID,
			secret_base32 CHAR(26)
		);
		`
		_, err = db.ExecContext(ctx, sqlStmt)
		if err != nil {
			panic(err)
		}
	}

	// router setup
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		index := pages.Index()
		templ.Handler(index).ServeHTTP(w, r)
	})
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/favicon.ico")
	})
	r.Route("/auth", func(r chi.Router) {
		r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			login := pages.Login()
			templ.Handler(login).ServeHTTP(w, r)
		})

		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusMovedPermanently)
		})

		r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
			register := pages.Register()
			templ.Handler(register).ServeHTTP(w, r)
		})

		r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
			if err = r.ParseForm(); err != nil {
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

			hashedPassword, hashedPasswordErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if hashedPasswordErr != nil {
				log.Fatal("Fail to hash password")
			}

			sqlStmt := `
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
			_, err = db.ExecContext(r.Context(), sqlStmt, id, fullName, nationality, email, string(hashedPassword))
			if err != nil {
				log.Fatal("Fail to register account:", err)
			}

			http.Redirect(w, r, "/dashboard", http.StatusMovedPermanently)
		})

		r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
			// redirect to login page
			http.Redirect(w, r, "/auth/login", http.StatusMovedPermanently)
		})
	})
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		dashboard := pages.Dashboard()
		templ.Handler(dashboard).ServeHTTP(w, r)
	})

	server := http.Server{
		Handler:      r,
		Addr:         ":9000",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	log.Print("Running server at ", server.Addr)
	if err = server.ListenAndServe(); err != nil {
		panic(err)
	}
}
