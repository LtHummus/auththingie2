package user

import (
	"github.com/spf13/viper"
	"golang.org/x/text/secure/precis"
)

func cleanPassword(input string) (string, error) {
	// because we are adding in precis after the fact, this can break logins for folks that have bad passwords from
	// earlier versions (for some rason if they put control codes or other undesirable code points in there). This
	// exists as a safety hatch for admins to disable precis processing for passwords to allow people back in to their
	// accounts
	//
	if viper.GetBool("security.disable_precis") {
		return input, nil
	}
	return precis.OpaqueString.String(input)
}
