package mtoken

import "errors"

var (
	// ErrKeyPair is used for invalid private key.
	ErrKeyPair = errors.New("invalid key pair")

	// ErrVerifyPoP occers
	ErrVerifyPoP = errors.New("failed to verify proof of possession")

	// ErrTokenExpire occers
	ErrTokenExpire = errors.New("this token is expired")

	// ErrTokenIat occers
	ErrTokenIat = errors.New("this token cannot be used now")

	// ErrMutualTLSConnection is used when the connection is not TLS
	ErrMutualTLSConnection = errors.New("connection must be used mutual TLS")

	// ErrTokenStruct is used when the token struct is empty.
	ErrTokenStruct = errors.New("unknown token struct type")
)
