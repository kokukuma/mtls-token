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
	"time"
)

const (
	alg = crypto.SHA256
)

var (
	timeFunc = func() time.Time {
		return time.Now()
	}
)

// JWT represents JWT
type JWT struct {
	header RawHeader
	claims RawClaims
	// TODO: signing methodを追加.
	// これを設定するときに、headerの値も指定される形にする.
}

// NewJWT creates JWT
func NewJWT(header RawHeader, claims RawClaims) *JWT {
	return &JWT{
		header: header,
		claims: claims,
	}
}

// Encoding returns unsafe JWT
func (j *JWT) Encoding() (string, error) {
	h, err := marshalEncode(j.header)
	if err != nil {
		return "", err
	}

	// claims
	c, err := marshalEncode(j.claims)
	if err != nil {
		return "", err
	}

	e := fmt.Sprintf("%s.%s", h, c)

	return e, nil
}

func (j *JWT) signJWT(privateKey *rsa.PrivateKey) (string, error) {
	// header
	ss, err := j.Encoding()
	if err != nil {
		return "", err
	}

	// signature
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, alg, execSha256(ss))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", ss, base64.RawURLEncoding.EncodeToString(sig)), nil
}

// Parse returns JWT from jwtSTring
func Parse(jwtString string) (*JWT, error) {
	parts := strings.Split(jwtString, ".")
	if len(parts) <= 1 {
		return nil, errors.New("invalid jwt format")
	}

	jwt := &JWT{
		header: map[string]interface{}{},
		claims: map[string]interface{}{},
	}

	err := decodeUnmarshal(parts[0], &jwt.header)
	if err != nil {
		return nil, err
	}

	err = decodeUnmarshal(parts[1], &jwt.claims)
	if err != nil {
		return nil, err
	}

	return jwt, nil
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
