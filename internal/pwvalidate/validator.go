package pwvalidate

import (
	"context"

	"github.com/lthummus/auththingie2/internal/user"
)

type PasswordValidator interface {
	Validate(ctx context.Context, username string, password string, sourceIP string) (*user.User, error)
}

var _ error = &InvalidUsernamePasswordError{}

type InvalidUsernamePasswordError struct {
	AccountRemainingBeforeLocked int
	IPRemainingBeforeLocked      int
}

func (_ *InvalidUsernamePasswordError) Error() string {
	return "invalid username or password"
}

type AccountLockedError struct{}

func (_ *AccountLockedError) Error() string {
	return "account has been temporarily locked"
}

type IPBlockedError struct{}

func (_ *IPBlockedError) Error() string {
	return "ip has been temporarily blocked"
}
