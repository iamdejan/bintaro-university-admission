package router

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"bintaro-university-admission/internal/database"
)

type MiddlewareGroup interface {
	Authenticated(next http.Handler) http.Handler
}

type MiddlewareGroupImpl struct {
	db *sql.DB
}

func NewMiddlewareGroup(db *sql.DB) MiddlewareGroup {
	return &MiddlewareGroupImpl{
		db: db,
	}
}

type userCtx struct{}

func (m *MiddlewareGroupImpl) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, cookieErr := r.Cookie(cookieNameSessionToken)
		if cookieErr != nil && errors.Is(cookieErr, http.ErrNoCookie) {
			slog.ErrorContext(r.Context(), "Cookie not found", logKeyError, cookieErr)

			errorMsgCookie := http.Cookie{
				Name:     cookieNameErrorMessage,
				Value:    "Session expired. Please log in again.",
				Expires:  time.Now().Add(10 * time.Minute),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			}
			http.SetCookie(w, &errorMsgCookie)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if cookieErr != nil {
			slog.ErrorContext(r.Context(), "Cookie error", logKeyError, cookieErr)
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return
		}

		sessionToken := c.Value
		session, sessionErr := database.GetSession(r.Context(), m.db, sessionToken)
		if sessionErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Failed to get session in database",
				logKeyError,
				sessionErr,
			)
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return
		}

		if time.Now().After(session.ExpiryTime()) {
			slog.ErrorContext(r.Context(), "Cookie expired", logKeyError, cookieErr)

			if deleteSessionErr := database.DeleteSession(r.Context(), m.db, sessionToken); deleteSessionErr != nil {
				slog.ErrorContext(
					r.Context(),
					"Failed to delete session in database",
					logKeyError,
					deleteSessionErr,
				)
				http.Redirect(w, r, "/error", http.StatusSeeOther)
				return
			}

			errorMsgCookie := http.Cookie{
				Name:     cookieNameErrorMessage,
				Value:    "Session expired. Please log in again.",
				Expires:  time.Now().Add(10 * time.Minute),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			}
			http.SetCookie(w, &errorMsgCookie)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		user, userErr := database.GetUserByID(r.Context(), m.db, session.UserID)
		if userErr != nil {
			slog.ErrorContext(r.Context(), "User does not exist", logKeyError, cookieErr)

			if deleteSessionErr := database.DeleteSession(r.Context(), m.db, sessionToken); deleteSessionErr != nil {
				slog.ErrorContext(
					r.Context(),
					"Failed to delete session in database",
					logKeyError,
					deleteSessionErr,
				)
				http.Redirect(w, r, "/error", http.StatusSeeOther)
				return
			}

			errorMsgCookie := http.Cookie{
				Name:     cookieNameErrorMessage,
				Value:    "Session expired. Please log in again.",
				Expires:  time.Now().Add(10 * time.Minute),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			}
			http.SetCookie(w, &errorMsgCookie)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), userCtx{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
