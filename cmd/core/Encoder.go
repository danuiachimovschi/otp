package core

type Encoder string

type EncoderInterface interface {
	String() string
}

const (
	Base32 Encoder = "base32"
	Base64 Encoder = "base64"
)

func (e Encoder) String(value Encoder) string {
	switch value {
	case Base32:
		return "base32"
	case Base64:
		return "base64"
	}

	panic("unknown encoder")
}
