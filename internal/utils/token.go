package utils

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

const randomCharacters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

func GenerateRandomSessionToken(byteLength int) (string, error) {
	ret := make([]byte, byteLength)
	for i := 0; i < byteLength; i++ {
		randIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(randomCharacters))))
		if err != nil {
			return "", err
		}

		ret[i] = randomCharacters[randIdx.Int64()]
	}

	return base64.URLEncoding.Strict().EncodeToString(ret), nil
}
