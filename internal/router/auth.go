package router

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"bintaro-university-admission/internal/database"
	"bintaro-university-admission/internal/pages"
	"bintaro-university-admission/internal/utils"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const cookieNameSessionToken = "session_token"

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
		inputtedPassword := r.FormValue("password")

		user, userErr := database.GetUser(r.Context(), db, email)
		if userErr != nil {
			log.Fatal("User not found: ", userErr)
		}

		if err := utils.ValidatePassword(user.ExpectedPassword, inputtedPassword); err != nil {
			log.Fatal("Wrong password: ", err)
		}

		token, err := utils.GenerateRandomSessionToken(32)
		if err != nil {
			log.Fatal("Error on token generation: ", err)
		}

		tokenExpiry := time.Now().Add(1 * time.Hour)

		s := database.Session{
			ID:           uuid.NewString(),
			UserID:       user.ID,
			SessionToken: token,
			ExpiresAt:    tokenExpiry,
		}
		if insertErr := database.InsertSession(r.Context(), db, s); insertErr != nil {
			log.Fatal("Failed to insert session: ", err)
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
			log.Fatal("Fail to parse form: ", err)
		}

		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirmPassword")

		if password != confirmPassword {
			log.Fatal("password is not confirmed")
		}

		hashedPassword, hashedPasswordErr := utils.HashPassword(password)
		if hashedPasswordErr != nil {
			log.Fatal("Failed to hash password: ", hashedPasswordErr)
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
			log.Fatal("Fail to register account: ", insertError)
		}

		token, err := utils.GenerateRandomSessionToken(32)
		if err != nil {
			log.Fatal("Error on token generation: ", err)
		}

		tokenExpiry := time.Now().Add(1 * time.Hour)

		s := database.Session{
			ID:           uuid.NewString(),
			UserID:       createUserRequest.ID,
			SessionToken: token,
			ExpiresAt:    tokenExpiry,
		}
		if insertSessionErr := database.InsertSession(r.Context(), db, s); insertSessionErr != nil {
			log.Fatal("Error when saving session token: ", insertSessionErr)
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

	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
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
