package totp

const (
	validStartStep int64 = -1
	validEndStep   int64 = 1
)

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
