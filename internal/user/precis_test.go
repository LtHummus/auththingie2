package user

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanPassword(t *testing.T) {
	t.Run("no errors from precis where we don't expect", func(t *testing.T) {
		var testCases = []struct {
			name   string
			input  string
			output string
		}{
			{
				name:   "Basic ez test case",
				input:  "hello",
				output: "hello",
			},
			{
				name:   "with spaces",
				input:  "a b c d e",
				output: "a b c d e",
			},
			{
				name:   "should normalize unicode composite characters",
				input:  "héllo",
				output: "héllo",
			},
			{
				name:   "make sure we don't decompose and recompose",
				input:  "Å",
				output: "Å",
			},
			{
				name:   "support passwords with basic emoji",
				input:  "i like to eat 🍔 because they are tasty",
				output: "i like to eat 🍔 because they are tasty",
			},
		}

		for _, curr := range testCases {
			t.Run(curr.name, func(t *testing.T) {
				output, err := cleanPassword(curr.input)
				require.NoError(t, err)
				assert.Equal(t, curr.output, output)
			})
		}
	})

	t.Run("error out on banned passwords", func(t *testing.T) {
		var testCases = []struct {
			name  string
			input string
		}{
			{
				name:  "ZWJ emoji sequences",
				input: "🧑‍🔧",
			},
			{
				name:  "Password containing RTL isolates",
				input: "⁧45⁩",
			},
		}

		for _, curr := range testCases {
			t.Run(curr.name, func(t *testing.T) {
				_, err := cleanPassword(curr.input)
				assert.Error(t, err)
			})
		}
	})

	t.Run("disable cleaning if config is set that way", func(t *testing.T) {
		viper.Set("security.disable_precis", true)
		t.Cleanup(func() {
			viper.Set("security.disable_precis", false)
		})

		// this is a decomposed e with accent, which would normally be normalized and composed (NFC) as part
		// of precis processing, but we've disabled it
		input := "héllo"
		output, err := cleanPassword(input)
		require.NoError(t, err)
		assert.Equal(t, input, output)
	})

}
