package auth

import (
	"errors"
	"time"
)

// RawClaims is the claims of JWT
type RawClaims map[string]interface{}

// GetInt64 returns value as int64 related to the key.
func (r RawClaims) GetInt64(key string) (int64, error) {
	if _, ok := r[key]; !ok {
		return 0, errors.New("key is not found in claims")
	}
	switch v := r[key].(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	}
	return 0, errors.New("type is not much")
}

// VerifyExp is check exp
func (r RawClaims) VerifyExp() bool {
	exp, err := r.GetInt64("exp")
	if err != nil {
		return false
	}
	return exp > timeFunc().Unix()
}

// VerifyIat is check iat
func (r RawClaims) VerifyIat() bool {
	iat, err := r.GetInt64("iat")
	if err != nil {
		return false
	}
	return iat <= timeFunc().Unix()
}

// GetX5tS256 is check x5t#S256
func (r RawClaims) GetX5tS256() string {
	if cnf, ok := r["cnf"].(map[string]interface{}); ok {
		if s256, ok := cnf["x5t#S256"]; ok {
			if v, ok := s256.(string); ok {
				return v
			}
		}
	}
	return ""
}

// NewClaims creates claims
func NewClaims(claims RawClaims, thumbprint string) (RawClaims, error) {

	// add default claims
	claims = addTimeClaims(claims)

	// add default claims
	var err error
	claims, err = addX5tS256(claims, thumbprint)
	if err != nil {
		return claims, err
	}

	return claims, nil
}

func addTimeClaims(claims RawClaims) RawClaims {
	now := timeFunc()

	if _, err := claims.GetInt64("iat"); err != nil {
		claims["iat"] = now.Unix()
	}

	if _, err := claims.GetInt64("exp"); err != nil {
		iat := now
		if v, err := claims.GetInt64("iat"); err == nil {
			iat = time.Unix(v, 0)
		}
		claims["exp"] = iat.Add(time.Hour).Unix()
	}

	return claims
}

func addX5tS256(claims RawClaims, thumbprint string) (RawClaims, error) {
	if _, ok := claims["cnf"]; !ok {
		claims["cnf"] = RawClaims{
			"x5t#S256": thumbprint,
		}
		return claims, nil
	}

	if cnf, ok := claims["cnf"].(RawClaims); ok {
		if _, s256 := cnf["x5t#S256"]; !s256 {
			cnf["x5t#S256"] = thumbprint
			return claims, nil
		}
		return claims, nil
	}
	return nil, errors.New("cnf must be RawClaims")
}
