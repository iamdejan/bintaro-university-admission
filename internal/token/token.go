package token

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

const randomCharacters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

func GenerateRandom(byteLength int) (string, error) {
	ret := make([]byte, byteLength)
	for i := range byteLength {
		randIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(randomCharacters))))
		if err != nil {
			return "", err
		}

		ret[i] = randomCharacters[randIdx.Int64()]
	}

	return base64.URLEncoding.Strict().EncodeToString(ret), nil
}
