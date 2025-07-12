package token

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandom(byteLength int) (string, error) {
	ret := make([]byte, byteLength)
	if _, err := rand.Read(ret); err != nil {
		return "", err
	}

	return base64.URLEncoding.Strict().EncodeToString(ret), nil
}
