package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

const ()

// ES256 represent Signature algorithm.
type ES256 struct {
}

// Name returns alg name.
func (e ES256) Name() string {
	return "ES256"
}

type ecdsaSignature struct {
	R, S *big.Int
}

// Sign creates signature
func (e ES256) Sign(key interface{}, ss string) ([]byte, error) {
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Unexpected key type")
	}

	// Check the length of ecdsa key
	if k.Curve.Params().BitSize != 256 {
		return nil, errors.New("key length must be 256 as ES256")
	}

	// 1. Generate a digital signature
	r, s, err := ecdsa.Sign(rand.Reader, k, execSha256(ss))
	if err != nil {
		return nil, errors.New("Failed to sign")
	}

	// 2. octet sequences in big-endian order
	rByte := padding(r.Bytes(), 32)
	sByte := padding(s.Bytes(), 32)

	// 3. Concatenate the two octet sequences in the order R and then S.
	return append(rByte, sByte...), nil
}

func padding(b []byte, l int) []byte {
	pad := bytes.Repeat([]byte{}, l-len(b))
	return append(pad, b...)
}

// Verify exec verify signature
func (e ES256) Verify(key interface{}, ss string, sig []byte) error {
	k, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("Unexpected key type")
	}

	rByte := sig[:32]
	sByte := sig[32:]

	r := big.NewInt(0).SetBytes(rByte)
	s := big.NewInt(0).SetBytes(sByte)

	status := ecdsa.Verify(k, execSha256(ss), r, s)
	if status != true {
		return errors.New("Failed to verify")
	}
	return nil
}
