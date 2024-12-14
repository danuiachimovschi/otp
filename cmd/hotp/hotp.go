package hotp

import (
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"otp-library/cmd/core"
	"otp-library/cmd/utils"
)

var FailedToDecodeSecretKey = errors.New("failed to decode secret key")

func GenerateHOTP(otp *core.Otp, counter uint64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(otp.GetSecret())
	if err != nil {
		return "", FailedToDecodeSecretKey
	}

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	hash := hmac.New(otp.Algo.Hash, key)
	hash.Write(counterBytes)
	hmacResult := hash.Sum(nil)

	offset := hmacResult[len(hmacResult)-1] & 0x0F
	binaryCode := int32(binary.BigEndian.Uint32(hmacResult[offset:offset+4]) & 0x7FFFFFFF)

	modulo := int32(math.Pow10(otp.Digits))
	otpGenerated := binaryCode % modulo

	return fmt.Sprintf("%0*d", otp.Digits, otpGenerated), nil
}

func ValidateHOTP(otp *core.Otp, otpProvided string, counter uint64) (bool, error) {
	key, err := base32.StdEncoding.DecodeString(otp.GetSecret())
	if err != nil {
		return false, FailedToDecodeSecretKey
	}

	for i := -otp.Skew; i <= otp.Skew; i++ {
		adjustedCounter := counter + uint64(i)

		counterBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(counterBytes, adjustedCounter)

		hash := hmac.New(otp.Algo.Hash, key)
		hash.Write(counterBytes)
		hmacResult := hash.Sum(nil)

		offset := hmacResult[len(hmacResult)-1] & 0x0F
		binaryCode := int32(binary.BigEndian.Uint32(hmacResult[offset:offset+4]) & 0x7FFFFFFF)

		modulo := int32(math.Pow10(otp.Digits))
		otpGenerated := binaryCode % modulo

		if utils.FormatOTP(otpGenerated, otp.Digits) == otpProvided {
			return true, nil
		}
	}

	return false, nil
}
