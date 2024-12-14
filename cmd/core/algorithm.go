package core

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type AlgorithmInterface interface {
	String() string
	Hash() hash.Hash
}

type Algorithm int

const (
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) String() string {
	switch a {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	}

	panic("unknown algorithm")
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case SHA1:
		return sha1.New()
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	}

	panic("unknown algorithm")
}
