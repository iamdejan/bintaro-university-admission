package totp

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/url"
	"strconv"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	validStartStep int64 = -1
	validEndStep   int64 = 1

	DefaultOTPDigits = 8
	defaultAlgo      = "SHA512"

	issuer = "bintaro-university-admission"
)

var algoMap = map[string]func() hash.Hash{
	"SHA512": sha512.New,
}

func GenerateQRCode(secretBase32 string, email string) (string, error) {
	url := generateURL(secretBase32, email)
	png, err := qrcode.Encode(url, qrcode.Low, 256)
	if err != nil {
		return "", err
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func generateURL(secretBase32 string, email string) string {
	params := url.Values{
		"issuer":    []string{issuer},
		"secret":    []string{secretBase32},
		"algorithm": []string{defaultAlgo},
		"digits":    []string{strconv.FormatUint(DefaultOTPDigits, 10)},
		"period":    []string{strconv.FormatInt(validityPeriodInSeconds, 10)},
	}
	return fmt.Sprintf(
		"otpauth://totp/bintaro-university-admission:%s?%s",
		url.QueryEscape(email),
		params.Encode(),
	)
}

func GenerateOTPTokens(secretBase32 string) ([]string, error) {
	tokens := make([]string, 5)
	counterValue := generateCounterValue()

	var i = 0
	for timeStep := validStartStep; timeStep <= validEndStep; timeStep++ {
		//nolint:gosec // since counterValue is based on Unix epoch, it should not go to negative, hence no overflow.
		hash, err := generateHash(
			secretBase32,
			uint64(counterValue+timeStep),
		)
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
