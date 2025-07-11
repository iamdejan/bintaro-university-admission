package router

import (
	"database/sql"
	"net/http"

	"bintaro-university-admission/internal/pages"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(db *sql.DB) http.Handler {
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
		auth(r, db)
	})
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		dashboard := pages.Dashboard()
		templ.Handler(dashboard).ServeHTTP(w, r)
	})

	return r
}
