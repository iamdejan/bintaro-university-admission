package router

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"time"

	"bintaro-university-admission/internal/database"
	"bintaro-university-admission/internal/pages"
	"bintaro-university-admission/internal/password"
	"bintaro-university-admission/internal/token"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const cookieNameSessionToken = "session_token"

const logKeyError = "error"

//nolint:gocognit,funlen
func auth(r chi.Router, db *sql.DB) {
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		login := pages.Login()
		templ.Handler(login).ServeHTTP(w, r)
	})

	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			slog.ErrorContext(r.Context(), "Fail to parse form", logKeyError, err)
			os.Exit(1)
		}

		email := r.FormValue("email")
		inputtedPassword := r.FormValue("password")

		user, userErr := database.GetUser(r.Context(), db, email)
		if userErr != nil {
			slog.ErrorContext(r.Context(), "User not found", logKeyError, userErr)
			os.Exit(1)
		}

		if err := password.Validate(user.ExpectedPassword, inputtedPassword); err != nil {
			slog.ErrorContext(r.Context(), "Wrong password", logKeyError, err)
			os.Exit(1)
		}

		token, err := token.GenerateRandom(32)
		if err != nil {
			slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
			os.Exit(1)
		}

		tokenExpiry := time.Now().Add(1 * time.Hour)

		s := database.Session{
			ID:           uuid.NewString(),
			UserID:       user.ID,
			SessionToken: token,
			ExpiresAt:    tokenExpiry,
		}
		if insertErr := database.InsertSession(r.Context(), db, s); insertErr != nil {
			slog.ErrorContext(r.Context(), "Failed to insert session", logKeyError, err)
			os.Exit(1)
		}

		cookie := http.Cookie{
			Name:     cookieNameSessionToken,
			Value:    token,
			HttpOnly: true,
			Secure:   true,
			Expires:  tokenExpiry,
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
			slog.ErrorContext(r.Context(), "Failed to parse form", logKeyError, err)
			os.Exit(1)
		}

		pwd := r.FormValue("password")
		confirmPassword := r.FormValue("confirmPassword")

		if pwd != confirmPassword {
			slog.ErrorContext(r.Context(), "Password is not confirmed")
			os.Exit(1)
		}

		hashedPassword, hashedPasswordErr := password.Hash(pwd)
		if hashedPasswordErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Failed to hash password",
				logKeyError,
				hashedPasswordErr,
			)
			os.Exit(1)
		}

		fullName := r.FormValue("fullName")
		email := r.FormValue("email")
		nationality := r.FormValue("nationality")
		userID := uuid.NewString()

		createUserRequest := database.CreateUserRequest{
			ID:             userID,
			FullName:       fullName,
			Nationality:    nationality,
			Email:          email,
			HashedPassword: hashedPassword,
		}
		if insertError := database.InsertUser(r.Context(), db, createUserRequest); insertError != nil {
			slog.ErrorContext(r.Context(), "Fail to register account", logKeyError, insertError)
			os.Exit(1)
		}

		t, err := token.GenerateRandom(32)
		if err != nil {
			slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
			os.Exit(1)
		}

		tokenExpiry := time.Now().Add(1 * time.Hour)

		s := database.Session{
			ID:           uuid.NewString(),
			UserID:       createUserRequest.ID,
			SessionToken: t,
			ExpiresAt:    tokenExpiry,
		}
		if insertSessionErr := database.InsertSession(r.Context(), db, s); insertSessionErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Error when saving session token",
				logKeyError,
				insertSessionErr,
			)
			os.Exit(1)
		}

		cookie := http.Cookie{
			Name:     cookieNameSessionToken,
			Value:    t,
			HttpOnly: true,
			Secure:   true,
			Expires:  tokenExpiry,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, &cookie)

		http.Redirect(w, r, "/dashboard", http.StatusMovedPermanently)
	})

	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		c, cookieErr := r.Cookie(cookieNameSessionToken)
		if cookieErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Error when getting cookie",
				logKeyError,
				cookieErr,
			)
			os.Exit(1)
		}
		if deleteErr := database.DeleteSession(r.Context(), db, c.Value); deleteErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Error when deleting cookie",
				logKeyError,
				deleteErr,
			)
			os.Exit(1)
		}

		cookie := http.Cookie{
			Name:     cookieNameSessionToken,
			Value:    "",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, "/auth/login", http.StatusMovedPermanently)
	})
}
