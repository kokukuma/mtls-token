package auth

import (
	"errors"
	"time"
)

// RawClaims is the claims of JWT
type RawClaims map[string]interface{}

// VerifyExp is check exp
func (r RawClaims) VerifyExp() bool {
	if _, ok := r["exp"]; !ok {
		return false
	}
	if exp, ok := r["exp"].(int64); ok {
		now := timeFunc()
		return exp > now.Unix()
	}
	return true
}

// VerifyIat is check iat
func (r RawClaims) VerifyIat() bool {
	now := timeFunc()
	if _, ok := r["iat"]; !ok {
		return false
	}
	if iat, ok := r["iat"].(int64); !ok {
		return iat < now.Unix()
	}
	return true
}

// VerifyPoP is check x5t#S256
func (r RawClaims) VerifyPoP(tp string) bool {
	if x5t, ok := r["cnf"].(map[string]interface{}); ok {
		if s256, ok := x5t["x5t#S256"]; ok {
			if s256 == tp {
				return true
			}
		}
	}
	return false
}

// NewClaims creates claims
func NewClaims(claims RawClaims, thumbprint string) (RawClaims, error) {
	var err error
	claims = addTimeClaims(claims)
	claims, err = addX5tS256(claims, thumbprint)
	if err != nil {
		return claims, err
	}
	return claims, nil
}

func addTimeClaims(claims RawClaims) RawClaims {
	now := timeFunc()

	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}

	if _, ok := claims["exp"]; !ok {
		iat := now
		if t, ok := claims["iat"].(int64); ok {
			iat = time.Unix(t, 0)
		}
		claims["exp"] = iat.Add(time.Hour).Unix()
	}

	return claims
}

func addX5tS256(claims RawClaims, thumbprint string) (RawClaims, error) {
	if _, ok := claims["cnf"]; !ok {
		claims["cnf"] = map[string]interface{}{
			"x5t#S256": thumbprint,
		}
		return claims, nil
	}

	if _, ok := claims["cnf"].(map[string]interface{}); !ok {
		return nil, errors.New("cnf must be map[string]interface{}")
	}

	d := claims["cnf"].(map[string]interface{})
	if _, s256 := d["x5t#S256"]; !s256 {
		d["x5t#S256"] = thumbprint
		return claims, nil
	}
	return claims, nil
}
