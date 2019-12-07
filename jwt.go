package mtoken

import (
	"crypto"
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
	raw    string
	header RawHeader
	claims RawClaims
	method Method
}

// NewJWT creates JWT
func NewJWT(header RawHeader, claims RawClaims, method Method) *JWT {
	header["alg"] = method.Name()
	return &JWT{
		header: header,
		claims: claims,
		method: method,
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

	j.raw = fmt.Sprintf("%s.%s", h, c)
	return j.raw, nil
}

func (j *JWT) signJWT(privateKey interface{}) (string, error) {
	// header
	ss, err := j.Encoding()
	if err != nil {
		return "", err
	}

	// create signature
	sig, err := j.method.Sign(privateKey, ss)
	if err != nil {
		return "", err
	}

	// Add signature to jwt
	return fmt.Sprintf("%s.%s", ss, base64.RawURLEncoding.EncodeToString(sig)), nil
}

// Parse returns JWT from jwtSTring
func Parse(jwtString string) (*JWT, error) {
	parts := strings.Split(jwtString, ".")
	if len(parts) <= 1 {
		return nil, errors.New("invalid jwt format")
	}

	// header
	header := RawHeader{}
	err := decodeUnmarshal(parts[0], &header)
	if err != nil {
		return nil, err
	}
	alg, err := header.GetString("alg")
	if err != nil {
		return nil, err
	}
	method, err := ParseMethod(alg)
	if err != nil {
		return nil, err
	}

	// payload
	claims := RawClaims{}
	err = decodeUnmarshal(parts[1], &claims)
	if err != nil {
		return nil, err
	}

	jwt := NewJWT(
		header,
		claims,
		method,
	)
	// TODO: NewJWT修正したときに何とかする
	jwt.raw = jwtString

	return jwt, nil
}

func (j *JWT) verifyJWT(key interface{}) error {
	parts := strings.Split(j.raw, ".")
	if len(parts) != 3 {
		return errors.New("invalid token received, token must have 3 parts")
	}

	signedContent := parts[0] + "." + parts[1]
	signatureString, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	return j.method.Verify(key, signedContent, []byte(signatureString))
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
