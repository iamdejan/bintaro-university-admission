package totp

import "time"

const validityPeriodInSeconds int64 = 30

// generateCounterValue is a function to divide the current timestamp by 30 seconds.
// This function serves as a "step" / the duration in which an OTP is valid.
// This function returns int64 because we want to allow past OTPs to be validated if
// they are still within acceptable time range.
// Past OTPs are validated by subtracting current value with how many past timesteps allowed.
func generateCounterValue() int64 {
	return time.Now().Unix() / validityPeriodInSeconds
}
