package ftue

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

func TestWrite(path string) error {
	testFile := filepath.Join(filepath.Dir(path), ".writetest")
	log.Debug().Str("path", testFile).Msg("testing write")
	err := os.WriteFile(testFile, []byte{}, 0644)
	if err != nil {
		log.Warn().Err(err).Str("path", testFile).Msg("could not write file")
		return err
	}
	err = os.Remove(testFile)
	if err != nil {
		log.Warn().Err(err).Str("path", testFile).Msg("could not remove test file")
	}

	return nil
}

func GetRootDomain(requestURL *url.URL) string {
	host := requestURL.Host
	parts := strings.Split(host, ".")
	if len(parts) == 1 {
		return parts[0]
	}
	return fmt.Sprintf("%s.%s", parts[len(parts)-2], parts[len(parts)-1])
}
