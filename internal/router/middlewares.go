package router

import (
	"log/slog"
	"net/http"
	"time"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, cookieErr := r.Cookie(cookieNameSessionToken)
		if cookieErr != nil {
			slog.ErrorContext(r.Context(), "Cookie error", logKeyError, cookieErr)

			errorMsgCookie := http.Cookie{
				Name:     cookieNameErrorMessage,
				Value:    "You need to login",
				Expires:  time.Now().Add(10 * time.Minute),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, &errorMsgCookie)
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		// TODO dejan: check if session token exists in database or not
		sessionToken := c.Value
		_ = sessionToken

		next.ServeHTTP(w, r)
	})
}
