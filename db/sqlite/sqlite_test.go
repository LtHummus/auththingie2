package sqlite

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestFlags(t *testing.T) {
	tc := []struct {
		flags    webauthn.CredentialFlags
		expected int
	}{
		{
			flags: webauthn.CredentialFlags{
				UserPresent:    false,
				UserVerified:   false,
				BackupEligible: false,
				BackupState:    false,
			},
			expected: 0,
		},
		{
			flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
			},
			expected: 15,
		},
		{
			flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: false,
				BackupState:    false,
			},
			expected: 12,
		},
	}

	for _, curr := range tc {
		e := encodeFlags(curr.flags)
		assert.Equal(t, curr.expected, e)
		d := decodeFlags(e)
		assert.Equal(t, curr.flags, d)
	}

}
