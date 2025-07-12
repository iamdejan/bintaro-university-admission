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

	login := pages.Login()
	templ.Handler(login).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.ErrorContext(r.Context(), "Fail to parse form", logKeyError, err)
		os.Exit(1)
	}

	email := r.FormValue("email")
	inputtedPassword := r.FormValue("password")

	user, userErr := database.GetUserByEmail(r.Context(), h.db, email)
	if userErr != nil {
		slog.ErrorContext(r.Context(), "User not found", logKeyError, userErr)
		os.Exit(1)
	}

	if err := password.Validate(user.HashedPassword, inputtedPassword); err != nil {
		slog.ErrorContext(r.Context(), "Wrong password", logKeyError, err)
		os.Exit(1)
	}

	token, err := token.GenerateRandom(32)
	if err != nil {
		slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
		os.Exit(1)
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	s := database.NewSession(token, user.ID, tokenExpiry)
	if insertErr := database.InsertSession(r.Context(), h.db, s); insertErr != nil {
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
		Path:     "/",
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) Register(w http.ResponseWriter, r *http.Request) {
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

	register := pages.Register()
	templ.Handler(register).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostRegister(w http.ResponseWriter, r *http.Request) {
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

	createUserRequest := database.User{
		ID:             userID,
		FullName:       fullName,
		Nationality:    nationality,
		Email:          email,
		HashedPassword: hashedPassword,
	}
	if insertError := database.InsertUser(r.Context(), h.db, createUserRequest); insertError != nil {
		slog.ErrorContext(r.Context(), "Fail to register account", logKeyError, insertError)
		os.Exit(1)
	}

	t, err := token.GenerateRandom(32)
	if err != nil {
		slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
		os.Exit(1)
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
		os.Exit(1)
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
		os.Exit(1)
	}
	if deleteErr := database.DeleteSession(r.Context(), h.db, c.Value); deleteErr != nil {
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
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
