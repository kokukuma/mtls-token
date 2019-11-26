package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"time"
)

// IssueToken create token
func IssueToken(state *tls.ConnectionState, privateKey *rsa.PrivateKey, claims RawClaims) (string, error) {
	if state == nil {
		return "", ErrMutualTLSConnection
	}
	if privateKey == nil {
		return "", ErrKeyPair
	}
	if claims == nil {
		return "", ErrTokenStruct
	}

	tp, err := getThumbprintFromTLSState(state)
	if err != nil {
		return "", err
	}

	// TODO: こういうClaimの定義はどこが知るべきか？
	iat := time.Now()
	claims["iat"] = iat.Unix()
	claims["exp"] = iat.Add(time.Hour).Unix()
	claims["x5t"] = map[string]string{
		"S256": tp,
	}

	// header
	header := RawHeader{
		"kid": "",
		"alg": "",
		"typ": "JWT",
	}
	jwt := NewJWT(header, claims)

	return signJWT(privateKey, jwt)
}

// DecodeToken is decode token
func DecodeToken(state *tls.ConnectionState, jwtString string, publicKey *rsa.PublicKey) (*JWT, error) {
	if state == nil {
		return nil, ErrMutualTLSConnection
	}
	if publicKey == nil {
		return nil, ErrKeyPair
	}

	jwt, err := Parse(jwtString)
	if err != nil {
		return nil, err
	}

	// verify signature
	if err := verifyJWT(jwtString, publicKey); err != nil {
		return nil, err
	}

	// verify token claims
	// TODO: この検証ロジックはexpを知っているところで持つ
	if exp, ok := jwt.claims["exp"].(int64); ok {
		now := time.Now().Unix()
		if exp < now {
			return nil, ErrTokenExpire
		}
	}

	// proof-of-possession
	// TODO: この検証ロジックはexpを知っているところで持つ
	tp, err := getThumbprintFromTLSState(state)
	if err != nil {
		return nil, err
	}
	if x5t, ok := jwt.claims["x5t"].(map[string]string); ok {
		if s256, ok := x5t["S256"]; ok {
			if s256 != tp {
				return nil, ErrVerifyPoP
			}
		}
	}
	return jwt, nil
}

func getThumbprintFromTLSState(state *tls.ConnectionState) (string, error) {
	if state == nil {
		return "", ErrMutualTLSConnection
	}
	PeerCertificates := state.PeerCertificates
	if PeerCertificates == nil {
		return "", ErrMutualTLSConnection
	}

	if len(PeerCertificates) <= 0 {
		return "", ErrMutualTLSConnection
	}

	// The first one is the client certificate.
	cert := PeerCertificates[0]
	sum := sha256.Sum256(cert.Raw)
	tp := base64.RawURLEncoding.EncodeToString(sum[:])
	return tp, nil
}
