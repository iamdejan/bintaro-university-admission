package totp

import (
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
)

func generateHash(secretBase32 string, counterValue uint64) ([]byte, error) {
	// we always assume the secretBase32 is really encoded in base32.
	// If the caller doesn't use base32, it's their problem.
	secretBytes, err := base32.StdEncoding.DecodeString(secretBase32)
	if err != nil {
		return nil, err
	}

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counterValue)

	h := hmac.New(algoMap[defaultAlgo], secretBytes)
	if _, err = h.Write(counterBytes); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// truncateHashToInt is a function to truncate generated hash into integer.
// Logic taken from https://www.hendrik-erz.de/post/understanding-totp-two-factor-authentication-eli5
// with small adjustments.
func truncateHashToHashCode(hash []byte) uint64 {
	offset := hash[len(hash)-1] & 0b1111
	truncated := hash[offset : offset+4]
	codeNumber := uint64(binary.BigEndian.Uint32(truncated))
	return codeNumber & 0b1111111111111111111111111111111
}

var printFormatMap = map[int]string{
	6: "%06d",
	8: "%08d",
}

func truncateHashCodeToToken(hashCode uint64) string {
	modulo := uint64(math.Pow10(DefaultOTPDigits))
	hashCode %= modulo
	return fmt.Sprintf(printFormatMap[DefaultOTPDigits], hashCode)
}
