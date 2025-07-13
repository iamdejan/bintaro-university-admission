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
		slog.ErrorContext(r.Context(), "Cookie not found in request", logKeyError, cookieErr)

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
		slog.ErrorContext(r.Context(), "Cookie not found in database", logKeyError, sessionErr)

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
		slog.ErrorContext(r.Context(), "Cookie expired")

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
		return nil, errCookieExpired
	}

	user, userErr := m.userStore.GetByID(r.Context(), session.UserID)
	if userErr != nil && errors.Is(userErr, sql.ErrNoRows) {
		slog.ErrorContext(r.Context(), "User not found", logKeyError, userErr)

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
		return nil, errCookieExpired
	}

	// only allow general token
	if session.Type != expectedSessionType {
		slog.ErrorContext(
			r.Context(),
			"Wrong session type",
			logKeyUserID,
			user.ID,
			logKeySessionType,
			session.Type,
		)

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
		return nil, errWrongSessionType
	}

	return context.WithValue(r.Context(), userCtx{}, &user), nil
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
