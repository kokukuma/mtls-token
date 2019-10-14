package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	alg = crypto.SHA256
)

func encodeJWT(privateKey *rsa.PrivateKey, token Issuer) (string, error) {

	// header
	head, err := marshalEncode(token.getHeader())
	if err != nil {
		return "", err
	}

	// claims
	claims, err := marshalEncode(token)
	if err != nil {
		return "", err
	}

	// signature
	ss := fmt.Sprintf("%s.%s", head, claims)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, alg, execSha256(ss))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", ss, base64.RawURLEncoding.EncodeToString(sig)), nil
}

func decodeJWT(signedJWT string, token interface{}) error {
	// decode claims
	s := strings.Split(signedJWT, ".")
	if len(s) < 2 {
		return errors.New("invalid token received")
	}
	err := decodeUnmarshal(s[1], &token)
	if err != nil {
		return err
	}
	return nil
}

func verifyJWT(token string, key *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token received, token must have 3 parts")
	}

	signedContent := parts[0] + "." + parts[1]
	signatureString, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(key, alg, execSha256(signedContent), []byte(signatureString))
}

func execSha256(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

func marshalEncode(d interface{}) (string, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	e := base64.RawURLEncoding.EncodeToString(b)
	return e, nil
}

func decodeUnmarshal(s string, d interface{}) error {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(decoded, &d); err != nil {
		return err
	}
	return nil
}
