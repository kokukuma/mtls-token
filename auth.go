package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
)

// IssueToken create token
func IssueToken(state *tls.ConnectionState, privateKey interface{}, rc RawClaims) (string, error) {
	if state == nil {
		return "", ErrMutualTLSConnection
	}
	if privateKey == nil {
		return "", ErrKeyPair
	}
	if rc == nil {
		return "", ErrTokenStruct
	}

	tp, err := getThumbprintFromTLSState(state)
	if err != nil {
		return "", err
	}

	claims, err := NewClaims(rc, tp)
	if err != nil {
		return "", err
	}

	// TODO: headerはNewJWT内で作ればいいか.

	// header
	header := RawHeader{
		"kid": "sample_key",
		"alg": "RS256",
		"typ": "JWT",
	}
	// typやalgも指定はできるが, 指定しなくても
	jwt := NewJWT(header, claims)

	return jwt.signJWT(privateKey)
}

// DecodeToken is decode token
func DecodeToken(state *tls.ConnectionState, jwtString string, publicKey interface{}) (*JWT, error) {
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
	if err := jwt.verifyJWT(publicKey); err != nil {
		return nil, err
	}

	// verify token claims
	if !jwt.claims.VerifyIat() {
		return nil, ErrTokenIat
	}
	if !jwt.claims.VerifyExp() {
		return nil, ErrTokenExpire
	}

	// proof of possession
	tp, err := getThumbprintFromTLSState(state)
	if err != nil {
		return nil, err
	}
	if !jwt.claims.VerifyPoP(tp) {
		return nil, ErrVerifyPoP
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
