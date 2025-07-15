package router

import (
	"log/slog"
	"net/http"
	"time"
)

const cookieNameErrorMessage = "__Host-error_message"

func logAndSetErrorMessageCookie(
	w http.ResponseWriter,
	r *http.Request,
	logTitle string,
	originalError error,
	errorMessage string,
) {
	ctx := r.Context()
	slog.ErrorContext(ctx, logTitle, logKeyError, originalError)
	errorMsgCookie := http.Cookie{
		Name:     cookieNameErrorMessage,
		Value:    errorMessage,
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &errorMsgCookie)
}

func deleteCookie(w http.ResponseWriter, cookieName string) {
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
}
