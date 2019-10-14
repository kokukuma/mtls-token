package auth

import (
	"time"
)

// Verifyer is interface for verify token
type Verifyer interface {
	verifyClaims() error
	verifyPoP(string) error
}

// Issuer is use for Issue Token
type Issuer interface {
	// For creating header information
	getHeader() *Header

	// for change default values.
	CnfSet(string)
	IatSet(time.Time)
	ExpSet(time.Time)
}

// Header represents the header for the signed JWS payloads.
type Header struct {
	Algorithm string `json:"alg"`
	Typ       string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

// Token is used as token of this auhtZ server.
type Token struct {
	// TODO: Delete this kid. How to set this value?
	Kid   string `json:"kid"`
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Sub   string `json:"sub"`

	// auto
	Cnf *Cnf  `json:"cnf"`
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

// Cnf is a field
type Cnf struct {
	X5T string `json:"x5t#S256"`
}

func (t *Token) getHeader() *Header {
	return &Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     t.Kid,
	}
}

// CnfSet is set cnf
func (t *Token) CnfSet(thumbprint string) {
	t.Cnf = &Cnf{
		X5T: thumbprint,
	}
}

// IatSet is set iat
func (t *Token) IatSet(ts time.Time) {
	t.Iat = ts.Unix()
}

// ExpSet is set iat
func (t *Token) ExpSet(ts time.Time) {
	t.Exp = ts.Unix()
}

func (t *Token) verifyClaims() error {
	now := time.Now().Unix()
	if t.Exp < now {
		return ErrTokenExpire
	}
	return nil
}

func (t *Token) verifyPoP(tp string) error {
	if t.Cnf.X5T != tp {
		return ErrVerifyPoP
	}
	return nil
}
