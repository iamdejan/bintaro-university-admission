package totp

import (
	"encoding/base64"
	"fmt"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	validStartStep int64 = -1
	validEndStep   int64 = 1
)

func GenerateQRCode(secretBase32 string, userID string) (string, error) {
	url := generateURL(secretBase32, userID)
	png, err := qrcode.Encode(url, qrcode.Low, 256)
	if err != nil {
		return "", err
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func generateURL(secretBase32 string, userID string) string {
	params := url.Values{
		"issuer":    []string{"bintaro-university-admission"},
		"secret":    []string{secretBase32},
		"algorithm": []string{"SHA1"},
		"digits":    []string{"6"},
		"period":    []string{fmt.Sprint(validityPeriodInSeconds)},
	}
	return fmt.Sprintf(
		"otpauth://totp/bintaro-university-admission:%s?%s",
		url.QueryEscape(userID),
		params.Encode(),
	)

}

func GenerateTokens(secretBase32 string) ([]string, error) {
	tokens := make([]string, 5)
	counterValue := generateCounterValue()

	var i = 0
	for timeStep := validStartStep; timeStep <= validEndStep; timeStep++ {
		hash, err := generateHash(secretBase32, uint64(counterValue+timeStep))
		if err != nil {
			return nil, err
		}

		hashCode := truncateHashToHashCode(hash)
		validToken := truncateHashCodeToToken(hashCode)
		tokens[i] = validToken

		i++
	}

	return tokens, nil
}
