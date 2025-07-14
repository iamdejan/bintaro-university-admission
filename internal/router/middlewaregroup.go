package router

import (
	"context"
	"database/sql"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"bintaro-university-admission/internal/store"
)

var (
	errWrongSessionType = errors.New("wrong session type")
	errCookieExpired    = errors.New("cookie expired")
)

type MiddlewareGroup interface {
	Authenticated(next http.Handler) http.Handler
	OTPAllowed(next http.Handler) http.Handler
	XSSProtected(next http.Handler) http.Handler
	SecurityHeaders(next http.Handler) http.Handler
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
		ctx, err := m.validateSessionByType(w, r, store.SessionTypeGeneral)
		if err != nil {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *MiddlewareGroupImpl) OTPAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := m.validateSessionByType(w, r, store.SessionTypeOTP)
		if err != nil {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *MiddlewareGroupImpl) validateSessionByType(
	w http.ResponseWriter,
	r *http.Request,
	expectedSessionType store.SessionType,
) (context.Context, error) {
	c, cookieErr := r.Cookie(cookieNameSessionToken)
	if cookieErr != nil && errors.Is(cookieErr, http.ErrNoCookie) {
		logAndSetErrorMessageCookie(
			w,
			r,
			"Cookie not found in request",
			cookieErr,
			"Session expired. Please log in again.",
		)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, cookieErr
	}

	if cookieErr != nil {
		slog.ErrorContext(r.Context(), "Cookie error", logKeyError, cookieErr)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return nil, cookieErr
	}

	sessionToken := c.Value
	session, sessionErr := m.sessionStore.Get(r.Context(), sessionToken)
	if sessionErr != nil && errors.Is(sessionErr, sql.ErrNoRows) {
		logAndSetErrorMessageCookie(
			w,
			r,
			"Cookie not found in database",
			sessionErr,
			"Session expired. Please log in again.",
		)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, sessionErr
	}
	if sessionErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Failed to get session in database:",
			logKeyError,
			sessionErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return nil, sessionErr
	}

	if time.Now().After(session.ExpiryTime()) {
		if deleteSessionErr := m.sessionStore.Delete(r.Context(), sessionToken); deleteSessionErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Failed to delete session in database",
				logKeyError,
				deleteSessionErr,
			)
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return nil, deleteSessionErr
		}

		logAndSetErrorMessageCookie(
			w,
			r,
			"Cookie expired",
			errors.New("cookie is expired"),
			"Session expired. Please log in again.",
		)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, errCookieExpired
	}

	user, userErr := m.userStore.GetByID(r.Context(), session.UserID)
	if userErr != nil && errors.Is(userErr, sql.ErrNoRows) {
		if deleteSessionErr := m.sessionStore.Delete(r.Context(), sessionToken); deleteSessionErr != nil {
			slog.ErrorContext(
				r.Context(),
				"Failed to delete session in database",
				logKeyError,
				deleteSessionErr,
			)
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return nil, deleteSessionErr
		}

		logAndSetErrorMessageCookie(
			w,
			r,
			"User not found",
			userErr,
			"Session expired. Please log in again.",
		)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, errCookieExpired
	}

	if userErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Failed to get user from database",
			logKeyError,
			userErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return nil, userErr
	}

	if session.Type != expectedSessionType {
		logAndSetErrorMessageCookie(
			w,
			r,
			"Wrong session type",
			errors.New("wrong session type"),
			"Session expired. Please log in again.",
		)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, errWrongSessionType
	}

	return context.WithValue(r.Context(), userCtx{}, user), nil
}

var methodsNeedSanitazion = map[string]struct{}{
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodDelete: {},
}

func (m *MiddlewareGroupImpl) XSSProtected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		if _, need := methodsNeedSanitazion[r.Method]; need {
			if parseFormErr := r.ParseForm(); parseFormErr != nil {
				slog.ErrorContext(
					r.Context(),
					"Failed to parse form",
					logKeyError,
					parseFormErr,
				)
				http.Redirect(w, r, "/error", http.StatusSeeOther)
				return
			}
			for key, values := range r.Form {
				sanitizedValues := make([]string, len(values))
				for i, value := range values {
					sanitizedValues[i] = html.EscapeString(strings.TrimSpace(value))
				}
				r.Form[key] = sanitizedValues
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (m *MiddlewareGroupImpl) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set comprehensive CSP header
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data: https:",
			"connect-src 'self'",
		}

		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=()")

		next.ServeHTTP(w, r)
	})
}
