package router

import (
	"context"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"bintaro-university-admission/internal/store"
)

type MiddlewareGroup interface {
	Authenticated(next http.Handler) http.Handler
	Sanitized(next http.Handler) http.Handler
}

type MiddlewareGroupImpl struct {
	userStore    store.UserStore
	sessionStore store.SessionStore
}

func NewMiddlewareGroup(
	userStore store.UserStore,
	sessionStore store.SessionStore,
) MiddlewareGroup {
	return &MiddlewareGroupImpl{
		userStore:    userStore,
		sessionStore: sessionStore,
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
		session, sessionErr := m.sessionStore.Get(r.Context(), sessionToken)
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

			if deleteSessionErr := m.sessionStore.Delete(r.Context(), sessionToken); deleteSessionErr != nil {
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

		user, userErr := m.userStore.GetByID(r.Context(), session.UserID)
		if userErr != nil {
			slog.ErrorContext(r.Context(), "User does not exist", logKeyError, userErr)

			if deleteSessionErr := m.sessionStore.Delete(r.Context(), sessionToken); deleteSessionErr != nil {
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

var methodsNeedSanitazion = map[string]struct{}{
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodDelete: {},
}

func (m *MiddlewareGroupImpl) Sanitized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, need := methodsNeedSanitazion[r.Method]; need {
			for key, values := range r.Form {
				sanitizedValues := make([]string, len(values))
				for i, value := range values {
					sanitizedValues[i] = html.EscapeString(strings.TrimSpace(value))
				}
				r.Form[key] = sanitizedValues
			}
			next.ServeHTTP(w, r)
		}
	})
}
