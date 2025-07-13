package random

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
)

const defaultByteLength = 64

func generateBytes(byteLength int) ([]byte, error) {
	ret := make([]byte, byteLength)
	if _, err := rand.Read(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

func GenerateBase64(stringLength int) (string, error) {
	ret, err := generateBytes(defaultByteLength)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.Strict().EncodeToString(ret)[:stringLength], nil
}

func GenerateBase32(stringLength int) (string, error) {
	ret, err := generateBytes(defaultByteLength)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(ret)[:stringLength], nil
}
