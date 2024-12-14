package main

import (
	"fmt"
	"otp-library/cmd/core"
	"otp-library/cmd/hotp"
	"otp-library/cmd/totp"
)

func main() {
	otp := core.NewOtp()
	otp.GenerateSecret()

	totP, err := totp.GenerateTOTP(otp)
	if err != nil {
		fmt.Println(err)
	}

	hotP, err := hotp.GenerateHOTP(otp, 0)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(totP)
	fmt.Println(hotP)

	fmt.Println(hotp.ValidateHOTP(otp, totP, 0))
	fmt.Println(totp.ValidateTOTP(otp, hotP))
}
