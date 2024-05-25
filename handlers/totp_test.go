package handlers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html"
	"image"
	_ "image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/salt"
	enrollment "github.com/lthummus/auththingie2/totp"
	"github.com/lthummus/auththingie2/user"
)

var (
	dataURLRegex          = regexp.MustCompile(`data:image/png;base64,(.*?)"`)
	qrCodeDataRegex       = regexp.MustCompile(`^otpauth://totp/AuthThingie:regularuser\?algorithm=SHA1&digits=6&issuer=AuthThingie&period=30&secret=([A-Z0-9]{32})$`)
	enrollmentTicketRegex = regexp.MustCompile(`<input type="hidden" name="totp-enrollment-ticket" value="(.*)" />`)
	loginTicketRegex      = regexp.MustCompile(`<input type="hidden" name="totp-login-ticket" value="(.*)" />`)
)

func buildEnrollmentTicket(t *testing.T, userID string, seed string, expiration time.Time) string {
	et := enrollment.EnrollmentTicket{
		UserID:     userID,
		Seed:       seed,
		Expiration: expiration,
	}
	encoded, err := et.Encode()
	require.NoError(t, err)

	return encoded
}

func buildLoginTicket(t *testing.T, userID string, redirectURI string, expiration time.Time) string {
	lt := enrollment.LoginTicket{
		UserID:      userID,
		RedirectURI: redirectURI,
		Expiration:  expiration,
	}

	encoded, err := lt.Encode()
	require.NoError(t, err)

	return encoded
}

func TestEnv_HandleTOTPValidation(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("error if no validation data found", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/totp", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("database error", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(nil, errors.New("whoops"))

		v := url.Values{}
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "", time.Now().Add(5*time.Minute)))
		v.Add("totp-code", "000000")

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "database error")
	})

	t.Run("user not found error", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(nil, nil)

		v := url.Values{}
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "", time.Now().Add(5*time.Minute)))
		v.Add("totp-code", "000000")

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "user not found")
	})

	t.Run("no TOTP set", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Id:       "test-user",
			Username: "testuser",
			TOTPSeed: nil,
		}, nil)

		v := url.Values{}
		v.Add("totp-code", "000000")
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "", time.Now().Add(5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "tried to validate totp for user that does not have it enabled")
	})

	t.Run("wrong TOTP given", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Id:       "test-user",
			Username: "testuser",
			TOTPSeed: &sampleTOTPSeed,
		}, nil)

		v := url.Values{}
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "", time.Now().Add(5*time.Minute)))
		v.Add("totp-code", "000000")

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Incorrect TOTP Code")

		// make sure no session data was written
		assert.Len(t, w.Result().Cookies(), 0)
	})

	t.Run("correct TOTP code", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Id:       "test-user",
			Username: "testuser",
			TOTPSeed: &sampleTOTPSeed,
		}, nil)

		correctTOTP, err := totp.GenerateCode(sampleTOTPSeed, time.Now())
		require.NoError(t, err)

		v := url.Values{}
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "", time.Now().Add(5*time.Minute)))
		v.Add("totp-code", correctTOTP)

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/", redirectURL.Path)
		assert.Len(t, w.Result().Cookies(), 1)

		var sess session.Session
		sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())
		err = sc.Decode(session.SessionCookieName, w.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.Equal(t, sess.UserID, "test-user")
	})

	t.Run("can't proceed if account is disabled", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Id:       "test-user",
			Username: "testuser",
			TOTPSeed: &sampleTOTPSeed,
			Disabled: true,
		}, nil)

		correctTOTP, err := totp.GenerateCode(sampleTOTPSeed, time.Now())
		require.NoError(t, err)

		v := url.Values{}
		v.Add("totp-code", correctTOTP)
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "", time.Now().Add(5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())

		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error: Account is disabled")
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("correct TOTP code with redirect", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Id:       "test-user",
			Username: "testuser",
			TOTPSeed: &sampleTOTPSeed,
		}, nil)

		correctTOTP, err := totp.GenerateCode(sampleTOTPSeed, time.Now())
		require.NoError(t, err)

		v := url.Values{}
		v.Add("totp-code", correctTOTP)
		v.Add(totpLoginTicketFieldName, buildLoginTicket(t, "test-user", "https://test.example.com/something", time.Now().Add(5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/totp", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "https", redirectURL.Scheme)
		assert.Equal(t, "test.example.com", redirectURL.Host)
		assert.Equal(t, "/something", redirectURL.Path)

		assert.Len(t, w.Result().Cookies(), 1)
	})

}

func TestEnv_HandleTOTPDisable(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("not logged in", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/disable_totp", nil, passesCSRF())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be logged in to do this")
	})

	t.Run("already has totp disabled", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/disable_totp", nil, passesCSRF(), withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "totp is already disabled")
	})

	t.Run("db write error", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("30 rock is a pretty good show"))

		r := makeTestRequest(t, http.MethodPost, "/disable_totp", nil, passesCSRF(), withUser(sampleNonAdminWithTOTP, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not save updated user to database")
	})

	t.Run("everything is ok", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		r := makeTestRequest(t, http.MethodPost, "/disable_totp", nil, passesCSRF(), withUser(sampleNonAdminWithTOTP, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You do not currently have TOTP enabled")

		updatedUser := db.Mock.Calls[1].Arguments[1].(*user.User)
		assert.Nil(t, updatedUser.TOTPSeed)
		assert.False(t, updatedUser.TOTPEnabled())
	})
}

func TestEnv_HandleTOTPSetup(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("setup -- not logged in", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/enable_totp", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	})

	t.Run("setup -- already enrolled", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/enable_totp", nil, withUser(sampleNonAdminWithTOTP, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you already have totp enabled")
	})

	// TODO: already have enrollment data

	t.Run("enrollment data generated", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/enable_totp", nil, passesCSRF(), withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		// pull the data URL out of the HTML body
		matches := dataURLRegex.FindStringSubmatch(w.Body.String())
		assert.Len(t, matches, 2)

		qrCodeDataURL := html.UnescapeString(matches[1])
		qrCodeImageBytes, err := base64.StdEncoding.DecodeString(qrCodeDataURL)
		assert.NoError(t, err)

		// decode the QR code from the page
		img, format, err := image.Decode(bytes.NewReader(qrCodeImageBytes))
		assert.NoError(t, err)
		assert.Equal(t, "png", format)

		bmp, err := gozxing.NewBinaryBitmapFromImage(img)
		assert.NoError(t, err)

		data, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
		assert.NoError(t, err)

		// make sure the data url from the QR code matches the TOTP enrollment scheme
		assert.Regexp(t, qrCodeDataRegex, data.String())

		// pull the TOTP secret from the qr code
		qrMatches := qrCodeDataRegex.FindStringSubmatch(data.String())
		assert.Len(t, qrMatches, 2)

		ticketMatches := enrollmentTicketRegex.FindStringSubmatch(w.Body.String())
		assert.Len(t, ticketMatches, 2)

		et, err := enrollment.DecodeEnrollmentTicket(ticketMatches[1])
		assert.NoError(t, err)

		assert.Equal(t, et.Seed, qrMatches[1])
		assert.Equal(t, sampleNonAdminUser.Id, et.UserID)
	})

	t.Run("post -- invalid session data", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/enable_totp", nil, passesCSRF())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "no enrollment ticket in request")
	})

	t.Run("post -- expired session data", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		q := url.Values{}
		q.Set(totpEnrollmentTicketFieldName, buildEnrollmentTicket(t, sampleNonAdminUser.Id, "AAAAAAAAAA", time.Now().Add(-5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/enable_totp", strings.NewReader(q.Encode()), passesCSRF(), withUser(sampleNonAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error: TOTP Enrollment Has Expired")
	})

	t.Run("post -- submitted code missing", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		q := url.Values{}
		q.Set(totpEnrollmentTicketFieldName, buildEnrollmentTicket(t, sampleNonAdminUser.Id, "AAAAAAAAAA", time.Now().Add(5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/enable_totp", strings.NewReader(q.Encode()), passesCSRF(), withUser(sampleNonAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error: TOTP Code Can Not Be Blank")
	})

	t.Run("post -- incorrect totp code", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Set(totpEnrollmentTicketFieldName, buildEnrollmentTicket(t, sampleNonAdminUser.Id, "AAAAAAAAAA", time.Now().Add(5*time.Minute)))
		v.Add("totp-code", "000000")

		r := makeTestRequest(t, http.MethodPost, "/enable_totp", strings.NewReader(v.Encode()), passesCSRF(), withUser(sampleNonAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error: Incorrect TOTP Code")
	})

	t.Run("post -- database error on write", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("UpdateTOTPSeed", mock.Anything, sampleNonAdminUser.Id, sampleTOTPSeed).Return(errors.New("bad bad bad"))

		code, err := totp.GenerateCode(sampleTOTPSeed, time.Now())
		assert.NoError(t, err)

		v := url.Values{}
		v.Add("totp-code", code)
		v.Add(totpEnrollmentTicketFieldName, buildEnrollmentTicket(t, sampleNonAdminUser.Id, sampleTOTPSeed, time.Now().Add(5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/enable_totp", strings.NewReader(v.Encode()), passesCSRF(), withUser(sampleNonAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not update totp secret in database")
	})

	t.Run("post -- everything ok", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		db.On("UpdateTOTPSeed", mock.Anything, sampleNonAdminUser.Id, sampleTOTPSeed).Return(nil)

		code, err := totp.GenerateCode(sampleTOTPSeed, time.Now())
		assert.NoError(t, err)

		v := url.Values{}
		v.Add("totp-code", code)
		v.Add(totpEnrollmentTicketFieldName, buildEnrollmentTicket(t, sampleNonAdminUser.Id, sampleTOTPSeed, time.Now().Add(5*time.Minute)))

		r := makeTestRequest(t, http.MethodPost, "/enable_totp", strings.NewReader(v.Encode()), passesCSRF(), withUser(sampleNonAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/edit_self", redirectURL.Path)
	})

}
