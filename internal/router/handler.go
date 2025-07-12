package router

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"bintaro-university-admission/internal/database"
	"bintaro-university-admission/internal/pages"
	"bintaro-university-admission/internal/password"
	"bintaro-university-admission/internal/token"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

type HandlerGroup interface {
	Index(w http.ResponseWriter, r *http.Request)

	Register(w http.ResponseWriter, r *http.Request)
	PostRegister(w http.ResponseWriter, r *http.Request)

	Login(w http.ResponseWriter, r *http.Request)
	PostLogin(w http.ResponseWriter, r *http.Request)

	Dashboard(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
}

type HandlerGroupImpl struct {
	db *sql.DB
}

func NewHandlerGroup(db *sql.DB) HandlerGroup {
	return &HandlerGroupImpl{
		db: db,
	}
}

func (h *HandlerGroupImpl) Index(w http.ResponseWriter, r *http.Request) {
	index := pages.Index()
	templ.Handler(index).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) Login(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(cookieNameErrorMessage)
	var errorMessage string
	if c != nil {
		errorMessage = c.Value
	}
	login := pages.Login(errorMessage)

	cookie := http.Cookie{
		Name:     cookieNameErrorMessage,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)

	templ.Handler(login).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.WarnContext(r.Context(), "Fail to parse form", logKeyError, err)
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "Invalid form",
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

	email := r.FormValue("email")
	inputtedPassword := r.FormValue("password")

	user, userErr := database.GetUserByEmail(r.Context(), h.db, email)
	if userErr != nil {
		slog.ErrorContext(
			r.Context(),
			"User not found",
			logKeyError,
			userErr,
			logKeyEmail,
			email,
			logKeyUserID,
			user.ID,
		)
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "Wrong email / password",
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

	if err := password.Validate(user.HashedPassword, inputtedPassword); err != nil {
		slog.ErrorContext(
			r.Context(),
			"Wrong password",
			logKeyError,
			err,
			logKeyEmail,
			email,
			logKeyUserID,
			user.ID,
		)
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "Wrong email / password",
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

	token, err := token.GenerateRandom(32)
	if err != nil {
		slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	s := database.NewSession(token, user.ID, tokenExpiry)
	if insertErr := database.InsertSession(r.Context(), h.db, s); insertErr != nil {
		slog.ErrorContext(r.Context(), "Failed to insert session", logKeyError, insertErr)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	cookie := http.Cookie{
		Name:     cookieNameSessionToken,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		Expires:  tokenExpiry,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) Register(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(cookieNameErrorMessage)
	var errorMessage string
	if c != nil {
		errorMessage = c.Value
	}
	register := pages.Register(errorMessage)

	cookie := http.Cookie{
		Name:     cookieNameErrorMessage,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)

	templ.Handler(register).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.ErrorContext(r.Context(), "Failed to parse form", logKeyError, err)
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "You need to fill in all of the fields",
			Expires:  time.Now().Add(10 * time.Minute),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		}
		http.SetCookie(w, &errorMsgCookie)
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	pwd := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if pwd != confirmPassword {
		slog.ErrorContext(r.Context(), "Password is not confirmed")
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "Password and Confirm Password must match",
			Expires:  time.Now().Add(10 * time.Minute),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		}
		http.SetCookie(w, &errorMsgCookie)
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	hashedPassword, hashedPasswordErr := password.Hash(pwd)
	if hashedPasswordErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Failed to hash password",
			logKeyError,
			hashedPasswordErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	fullName := r.FormValue("fullName")
	email := r.FormValue("email")
	nationality := r.FormValue("nationality")
	userID := uuid.NewString()

	createUserRequest := database.User{
		ID:             userID,
		FullName:       fullName,
		Nationality:    nationality,
		Email:          email,
		HashedPassword: hashedPassword,
	}
	if insertError := database.InsertUser(r.Context(), h.db, createUserRequest); insertError != nil {
		slog.ErrorContext(r.Context(), "Fail to register account", logKeyError, insertError)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	t, err := token.GenerateRandom(32)
	if err != nil {
		slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	s := database.NewSession(t, userID, tokenExpiry)
	if insertSessionErr := database.InsertSession(r.Context(), h.db, s); insertSessionErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Error when saving session token",
			logKeyError,
			insertSessionErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	cookie := http.Cookie{
		Name:     cookieNameSessionToken,
		Value:    t,
		HttpOnly: true,
		Secure:   true,
		Expires:  tokenExpiry,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := ctx.Value(userCtx{}).(*database.User)
	dashboard := pages.Dashboard(user.FullName)
	templ.Handler(dashboard).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) Logout(w http.ResponseWriter, r *http.Request) {
	c, cookieErr := r.Cookie(cookieNameSessionToken)
	if cookieErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Error when getting cookie",
			logKeyError,
			cookieErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}
	if deleteErr := database.DeleteSession(r.Context(), h.db, c.Value); deleteErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Error when deleting cookie",
			logKeyError,
			deleteErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	cookie := http.Cookie{
		Name:     cookieNameSessionToken,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
