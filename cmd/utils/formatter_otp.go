package utils

import "fmt"

func FormatOTP(otp int32, digits int) string {
	return fmt.Sprintf("%0*d", digits, otp)
}
