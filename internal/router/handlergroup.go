package router

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"bintaro-university-admission/internal/password"
	"bintaro-university-admission/internal/random"
	"bintaro-university-admission/internal/store"
	"bintaro-university-admission/internal/totp"
	"bintaro-university-admission/internal/ui/pages"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

const (
	sessionTokenLength = 64
	secretLength       = 32

	validSessionDuration = 1 * time.Hour
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
	deleteCookie(w, cookieNameErrorMessage)
	templ.Handler(login).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		logAndSetErrorMessageCookie(w, r, "Fail to parse form", err, "Invalid form data")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	inputtedPassword := r.FormValue("password")

	user, err := h.userStore.GetByEmail(ctx, email)
	if err != nil {
		logAndSetErrorMessageCookie(w, r, "User not found", err, "Wrong email / password")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err = password.Validate(user.HashedPassword, inputtedPassword); err != nil {
		logAndSetErrorMessageCookie(w, r, "Wrong password", err, "Wrong email / password")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	mfa, mfaErr := h.mfaStore.GetByUserID(ctx, user.ID)
	if mfaErr != nil && !errors.Is(mfaErr, sql.ErrNoRows) {
		slog.ErrorContext(ctx, "Failed to get MFA from database", logKeyError, mfaErr)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	if mfa == nil {
		if err = h.generateAndSetToken(w, r, user.ID, store.SessionTypeGeneral); err != nil {
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if err = h.generateAndSetToken(w, r, user.ID, store.SessionTypeOTP); err != nil {
		return
	}
	http.Redirect(w, r, "/login/validate-otp", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) ValidateOTP(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(cookieNameErrorMessage)
	var errorMessage string
	if c != nil {
		errorMessage = c.Value
	}
	validateOTP := pages.ValidateOTP(errorMessage)
	deleteCookie(w, cookieNameErrorMessage)
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
	deleteCookie(w, cookieNameErrorMessage)
	templ.Handler(register).ServeHTTP(w, r)
}

func (h *HandlerGroupImpl) PostRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		logAndSetErrorMessageCookie(
			w,
			r,
			"Failed to parse form",
			err,
			"You need to fill in all of the fields",
		)
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	pwd := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if pwd != confirmPassword {
		logAndSetErrorMessageCookie(
			w,
			r,
			"Password is not confirmed",
			errors.New("password is not confirmed"),
			"Password and Confirm Password must match",
		)
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
		logAndSetErrorMessageCookie(
			w,
			r,
			"User already exists",
			errors.New("user already exists"),
			"User already exists",
		)
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

	if err := h.generateAndSetToken(w, r, userID, store.SessionTypeGeneral); err != nil {
		return
	}
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

	c, _ := r.Cookie(cookieNameErrorMessage)
	if c != nil {
		props.ErrorMessage = c.Value
	}

	deleteCookie(w, cookieNameErrorMessage)

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

	qrCode, err := totp.GenerateQRCode(secretBase32, user.Email)
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
		logAndSetErrorMessageCookie(w, r, "Fail to parse form", err, "Invalid form data")
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

	isValid := slices.Contains(validOTPTokens, inputtedOTPToken)
	if !isValid {
		logAndSetErrorMessageCookie(w, r, "Invalid OTP", errors.New("invalid OTP"), "Invalid OTP")
		http.Redirect(w, r, redirectURLIfInvalid, http.StatusSeeOther)
		return
	}

	if err = h.generateAndSetToken(w, r, user.ID, store.SessionTypeGeneral); err != nil {
		return
	}
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

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) Logout(w http.ResponseWriter, r *http.Request) {
	c, cookieErr := r.Cookie(store.CookieNameSessionToken)
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

	deleteCookie(w, store.CookieNameSessionToken)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *HandlerGroupImpl) generateAndSetToken(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
	sessionType store.SessionType,
) error {
	ctx := r.Context()
	token, err := random.GenerateBase64(sessionTokenLength)
	if err != nil {
		slog.ErrorContext(ctx, "Error on token generation", logKeyError, err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return err
	}

	s := store.NewSession(token, userID, sessionType, time.Now().Add(validSessionDuration))
	if insertErr := h.sessionStore.Insert(ctx, s); insertErr != nil {
		slog.ErrorContext(ctx, "Failed to insert session", logKeyError, insertErr)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return insertErr
	}

	http.SetCookie(w, s.Cookie())
	return nil
}
