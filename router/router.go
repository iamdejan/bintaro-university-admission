package router

import (
	"database/sql"
	"log"
	"net/http"

	"bintaro-university-admission/pages"
	"bintaro-university-admission/utils"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func NewRouter(db *sql.DB) http.Handler {
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
			_, err := db.ExecContext(r.Context(), sqlStmt, id, fullName, nationality, email, string(hashedPassword))
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

	return r
}
