package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type RS256 struct {
}

// Sign creates signature
func (r RS256) Sign(key interface{}, ss string) ([]byte, error) {
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Unexpected key type")
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, k, alg, execSha256(ss))
	if err != nil {
		return nil, err
	}
	return sig, nil
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
