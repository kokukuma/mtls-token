package mtoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// RS256 represent Signature algorithm.
type RS256 struct {
}

// Name returns alg name.
func (r RS256) Name() string {
	return "RS256"
}

// Sign creates signature
func (r RS256) Sign(key interface{}, ss string) ([]byte, error) {
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Unexpected key type")
	}
	return rsa.SignPKCS1v15(rand.Reader, k, alg, execSha256(ss))
}

// Verify exec verify signature
func (r RS256) Verify(key interface{}, ss string, sig []byte) error {

	k, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("Unexpected key type")
	}
	return rsa.VerifyPKCS1v15(k, alg, execSha256(ss), sig)
}

func execSha256(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}
