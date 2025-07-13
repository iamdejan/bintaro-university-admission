package router

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"bintaro-university-admission/internal/pages"
	"bintaro-university-admission/internal/password"
	"bintaro-university-admission/internal/random"
	"bintaro-university-admission/internal/store"
	"bintaro-university-admission/internal/totp"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

const (
	sessionTokenLength = 64
	secretLength       = 32
)

type HandlerGroup interface {
	Index(w http.ResponseWriter, r *http.Request)

	Register(w http.ResponseWriter, r *http.Request)
	PostRegister(w http.ResponseWriter, r *http.Request)

	Login(w http.ResponseWriter, r *http.Request)
	PostLogin(w http.ResponseWriter, r *http.Request)
	ValidateOTP(w http.ResponseWriter, r *http.Request)
	PostValidateOTP(w http.ResponseWriter, r *http.Request)

	Dashboard(w http.ResponseWriter, r *http.Request)

	TOTPSetup(w http.ResponseWriter, r *http.Request)
	PostTOTPSetup(w http.ResponseWriter, r *http.Request)
	CancelTOTPSetup(w http.ResponseWriter, r *http.Request)

	Logout(w http.ResponseWriter, r *http.Request)
}

type HandlerGroupImpl struct {
	userStore    store.UserStore
	sessionStore store.SessionStore
	mfaStore     store.MultiFactorAuthStore
}

var _ HandlerGroup = (*HandlerGroupImpl)(nil)

func NewHandlerGroup(
	userStore store.UserStore,
	sessionStore store.SessionStore,
	mfaStore store.MultiFactorAuthStore,
) HandlerGroup {
	return &HandlerGroupImpl{
		userStore:    userStore,
		sessionStore: sessionStore,
		mfaStore:     mfaStore,
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
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		slog.WarnContext(ctx, "Fail to parse form", logKeyError, err)
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

	user, userErr := h.userStore.GetByEmail(ctx, email)
	if userErr != nil {
		slog.ErrorContext(
			ctx,
			"User not found",
			logKeyError,
			userErr,
			logKeyEmail,
			email,
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
			ctx,
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

	token, err := random.GenerateBase64(sessionTokenLength)
	if err != nil {
		slog.ErrorContext(ctx, "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	mfa, err := h.mfaStore.GetByUserID(ctx, user.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.ErrorContext(ctx, "Failed to get MFA from database", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	if mfa == nil {
		s := store.NewSession(token, user.ID, store.SessionTypeGeneral, tokenExpiry)
		if insertErr := h.sessionStore.Insert(ctx, s); insertErr != nil {
			slog.ErrorContext(ctx, "Failed to insert session", logKeyError, insertErr)
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
		return
	}

	s := store.NewSession(token, user.ID, store.SessionTypeOTP, tokenExpiry)
	if insertErr := h.sessionStore.Insert(ctx, s); insertErr != nil {
		slog.ErrorContext(ctx, "Failed to insert session", logKeyError, insertErr)
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
	http.Redirect(w, r, "/login/validate-otp", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) ValidateOTP(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(cookieNameErrorMessage)
	var errorMessage string
	if c != nil {
		errorMessage = c.Value
	}
	validateOTP := pages.ValidateOTP(errorMessage)

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
	templ.Handler(validateOTP).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostValidateOTP(w http.ResponseWriter, r *http.Request) {
	h.validateOTP(w, r, "/login")
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

	existingUser, existingUserErr := h.userStore.GetByEmail(r.Context(), email)
	if existingUserErr != nil && !errors.Is(existingUserErr, sql.ErrNoRows) {
		slog.ErrorContext(
			r.Context(),
			"Failed to query existing user",
			logKeyError,
			existingUserErr,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	if existingUser != nil {
		slog.ErrorContext(
			r.Context(),
			"User already exists",
		)
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "User already exists",
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

	createUserRequest := store.User{
		ID:             userID,
		FullName:       fullName,
		Nationality:    nationality,
		Email:          email,
		HashedPassword: hashedPassword,
	}
	if insertError := h.userStore.Insert(r.Context(), createUserRequest); insertError != nil {
		slog.ErrorContext(r.Context(), "Fail to register account", logKeyError, insertError)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	t, err := random.GenerateBase64(sessionTokenLength)
	if err != nil {
		slog.ErrorContext(r.Context(), "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	s := store.NewSession(t, userID, store.SessionTypeGeneral, tokenExpiry)
	if insertSessionErr := h.sessionStore.Insert(r.Context(), s); insertSessionErr != nil {
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
	user, _ := ctx.Value(userCtx{}).(*store.User)

	props := pages.DashboardProps{
		FullName: user.FullName,
	}
	mfa, err := h.mfaStore.GetByUserID(r.Context(), user.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.ErrorContext(
			r.Context(),
			"Failed to get MFA from database",
			logKeyError,
			err,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	if mfa != nil {
		props.HasTOTPSetup = true
	}
	dashboard := pages.Dashboard(props)
	templ.Handler(dashboard).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := ctx.Value(userCtx{}).(*store.User)

	if err := h.mfaStore.DeleteByUserID(ctx, user.ID); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		slog.ErrorContext(
			ctx,
			"Failed to delete MFA from database",
			logKeyError,
			err,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	secretBase32, _ := random.GenerateBase32(secretLength)
	mfa := store.MultiFactorAuth{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		SecretBase32: secretBase32,
	}
	if err := h.mfaStore.Insert(ctx, mfa); err != nil {
		slog.ErrorContext(
			ctx,
			"Failed to insert MFA to database",
			logKeyError,
			err,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	qrCode, err := totp.GenerateQRCode(secretBase32, user.ID)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"Failed to generate QR code",
			logKeyError,
			err,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	props := pages.TOTPSetupProps{
		QRCodeImageBase64: qrCode,
		SecretBase32:      secretBase32,
	}
	totpSetup := pages.TOTPSetup(props)

	token, err := random.GenerateBase64(sessionTokenLength)
	if err != nil {
		slog.ErrorContext(ctx, "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	s := store.NewSession(token, user.ID, store.SessionTypeOTP, tokenExpiry)
	if insertErr := h.sessionStore.Insert(ctx, s); insertErr != nil {
		slog.ErrorContext(ctx, "Failed to insert session", logKeyError, insertErr)
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
	templ.Handler(totpSetup).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostTOTPSetup(w http.ResponseWriter, r *http.Request) {
	h.validateOTP(w, r, "/totp-setup")
}

func (h *HandlerGroupImpl) validateOTP(
	w http.ResponseWriter,
	r *http.Request,
	redirectURLIfInvalid string,
) {
	ctx := r.Context()
	user, _ := ctx.Value(userCtx{}).(*store.User)

	mfa, err := h.mfaStore.GetByUserID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(
				ctx,
				"MFA isn't setup for this account",
				logKeyError,
				err,
				logKeyUserID,
				user.ID,
			)

			http.Redirect(w, r, "/totp-setup", http.StatusSeeOther)
			return
		}

		slog.ErrorContext(
			ctx,
			"Failed to get MFA from database",
			logKeyError,
			err,
			logKeyUserID,
			user.ID,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	if err = r.ParseForm(); err != nil {
		slog.WarnContext(r.Context(), "Fail to parse form", logKeyError, err, logKeyUserID, user.ID)
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
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	inputtedOTPToken := r.Form["otp_code"][0]
	validOTPTokens, generateOTPErr := totp.GenerateOTPTokens(mfa.SecretBase32)
	if generateOTPErr != nil {
		slog.ErrorContext(
			r.Context(),
			"Fail to generate OTP",
			logKeyError,
			generateOTPErr,
			logKeyUserID,
			user.ID,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	isValid := false
	for _, token := range validOTPTokens {
		if token == inputtedOTPToken {
			isValid = true
			break
		}
	}
	if !isValid {
		errorMsgCookie := http.Cookie{
			Name:     cookieNameErrorMessage,
			Value:    "Invalid OTP",
			Expires:  time.Now().Add(10 * time.Minute),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		}
		http.SetCookie(w, &errorMsgCookie)
		http.Redirect(w, r, redirectURLIfInvalid, http.StatusSeeOther)
		return
	}

	token, err := random.GenerateBase64(sessionTokenLength)
	if err != nil {
		slog.ErrorContext(ctx, "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)

	s := store.NewSession(token, user.ID, store.SessionTypeGeneral, tokenExpiry)
	if insertErr := h.sessionStore.Insert(ctx, s); insertErr != nil {
		slog.ErrorContext(ctx, "Failed to insert session", logKeyError, insertErr)
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

func (h *HandlerGroupImpl) CancelTOTPSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := ctx.Value(userCtx{}).(*store.User)

	if err := h.mfaStore.DeleteByUserID(ctx, user.ID); err != nil {
		slog.ErrorContext(
			ctx,
			"Failed to delete MFA from database",
			logKeyError,
			err,
		)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	token, err := random.GenerateBase64(sessionTokenLength)
	if err != nil {
		slog.ErrorContext(ctx, "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)
	s := store.NewSession(token, user.ID, store.SessionTypeOTP, tokenExpiry)
	if insertErr := h.sessionStore.Insert(ctx, s); insertErr != nil {
		slog.ErrorContext(ctx, "Failed to insert session", logKeyError, insertErr)
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
	if deleteErr := h.sessionStore.Delete(r.Context(), c.Value); deleteErr != nil {
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
