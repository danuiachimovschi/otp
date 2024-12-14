package core

import (
	"encoding/base32"
	"math/rand"
)

const (
	DEFAULT_ALGO          = SHA1
	DEFAULT_SECRET_LENGTH = 32
	DEFAULT_PERIOD        = 30
	DEFAULT_DIGITS        = 6
	DEFAULT_ENCODER       = Base32
)

type Otp struct {
	secret  string
	Period  int
	Digits  int
	Skew    int
	Algo    Algorithm
	Encoder Encoder
}

func NewOtp() *Otp {
	return &Otp{
		Period:  DEFAULT_PERIOD,
		Digits:  DEFAULT_DIGITS,
		Skew:    0,
		Algo:    DEFAULT_ALGO,
		Encoder: DEFAULT_ENCODER,
	}
}

func (o *Otp) GenerateSecret() {
	secret := make([]byte, DEFAULT_SECRET_LENGTH)
	_, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}

	o.secret = base32.StdEncoding.EncodeToString(secret)
}

func (o *Otp) GetSecret() string {
	return o.secret
}

func (o *Otp) SetSecret(secret string) {
	o.secret = secret
}
