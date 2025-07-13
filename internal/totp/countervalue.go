package totp

import "time"

const VALIDITY_IN_SECONDS int64 = 30

// generateCounterValue is a function to divide the current timestamp by 30 seconds.
// This function serves as a "step" / the duration in which an OTP is valid.
// This function returns int64 because we want to allow past OTPs to be validated if
// they are still within acceptable time range. If we return uint64, we cannot subtract it.
func generateCounterValue() int64 {
	return time.Now().Unix() / VALIDITY_IN_SECONDS
}
