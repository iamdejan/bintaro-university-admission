package router

import (
	"net/http"

	"bintaro-university-admission/internal/pages"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(hg HandlerGroup, mg MiddlewareGroup) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger, mg.XSSProtected, mg.SecurityHeaders)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		index := pages.Index()
		templ.Handler(index).ServeHTTP(w, r)
	})
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/favicon.ico")
	})
	r.Get("/error", func(w http.ResponseWriter, r *http.Request) {
		errorPage := pages.Error()
		templ.Handler(errorPage).ServeHTTP(w, r)
	})
	r.Get("/login", hg.Login)
	r.Post("/login", hg.PostLogin)
	r.Get("/register", hg.Register)
	r.Post("/register", hg.PostRegister)
	r.With(mg.Authenticated).Get("/dashboard", hg.Dashboard)
	r.With(mg.Authenticated).Get("/totp-setup", hg.TOTPSetup)
	r.With(mg.Authenticated).Post("/totp-setup", hg.PostTOTPSetup)
	r.With(mg.Authenticated).Delete("/totp-setup", hg.CancelTOTPSetup)
	r.With(mg.Authenticated).Get("/logout", hg.Logout)

	return r
}
