package salt

import "github.com/go-webauthn/webauthn/protocol"

type payload struct {
	Version    int                       `json:"version"`
	Signing    protocol.URLEncodedBase64 `json:"signing"`
	Encryption protocol.URLEncodedBase64 `json:"encryption"`
}
