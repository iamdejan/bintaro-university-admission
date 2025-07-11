package main

import (
	"log"
	"net/http"
	"time"

	"bintaro-university-admission/pages"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
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
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
