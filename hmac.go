package mtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// HS256 represent Signature algorithm.
type HS256 struct {
}

// Name returns alg name.
func (r HS256) Name() string {
	return "HS256"
}

// Sign creates signature
func (r HS256) Sign(key interface{}, ss string) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, errors.New("Unexpected key type")
	}
	hasher := hmac.New(sha256.New, k)
	hasher.Write([]byte(ss))
	return hasher.Sum(nil), nil
}

// Verify exec verify signature
func (r HS256) Verify(key interface{}, ss string, sig []byte) error {

	k, ok := key.([]byte)
	if !ok {
		return errors.New("Unexpected key type")
	}
	hasher := hmac.New(sha256.New, k)
	hasher.Write([]byte(ss))
	if !hmac.Equal(hasher.Sum(nil), sig) {
		return errors.New("Failed to verify")
	}
	return nil
}
