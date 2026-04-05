package pwvalidate

import (
	"context"

	"github.com/lthummus/auththingie2/internal/user"
)

type PasswordValidator interface {
	Validate(ctx context.Context, username string, password string, sourceIP string) (*user.User, error)
}

type PasswordValidatorError interface {
	error
	isAuthError()
}

var (
	_ PasswordValidatorError = &InvalidUsernamePasswordError{}
	_ PasswordValidatorError = &AccountLockedError{}
	_ PasswordValidatorError = &IPBlockedError{}
	_ PasswordValidatorError = &AccountDisabledError{}
)

type InvalidUsernamePasswordError struct {
	AccountRemainingBeforeLocked int
	IPRemainingBeforeLocked      int
}

func (iupe *InvalidUsernamePasswordError) Error() string {
	return "invalid username or password"
}
func (iupe *InvalidUsernamePasswordError) isAuthError() {}

type AccountLockedError struct{}

func (ale *AccountLockedError) Error() string {
	return "account has been temporarily locked"
}
func (ale *AccountLockedError) isAuthError() {}

type IPBlockedError struct{}

func (ipbe *IPBlockedError) Error() string {
	return "ip has been temporarily blocked"
}
func (ipbe *IPBlockedError) isAuthError() {}

type AccountDisabledError struct{}

func (ade *AccountDisabledError) Error() string {
	return "account is disabled"
}
func (ade *AccountDisabledError) isAuthError() {}
