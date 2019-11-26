package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"time"
)

// IssueToken create token
func IssueToken(state *tls.ConnectionState, privateKey *rsa.PrivateKey, token Issuer) (string, error) {
	if state == nil {
		return "", ErrMutualTLSConnection
	}
	if privateKey == nil {
		return "", ErrKeyPair
	}
	if token == nil {
		return "", ErrTokenStruct
	}

	tp, err := getThumbprintFromTLSState(state)
	if err != nil {
		return "", err
	}

	// set cnf
	iat := time.Now()
	token.CnfSet(tp)
	token.IatSet(iat)
	token.ExpSet(iat.Add(time.Hour))

	// encode
	return encodeJWT(privateKey, token)
}

// DecodeToken is decode token
func DecodeToken(state *tls.ConnectionState, payload string, publicKey *rsa.PublicKey, token Verifyer) error {
	if state == nil {
		return ErrMutualTLSConnection
	}
	if publicKey == nil {
		return ErrKeyPair
	}
	if token == nil {
		return ErrTokenStruct
	}
	err := decodeJWT(payload, token)
	if err != nil {
		return err
	}

	// verify signature
	if err := verifyJWT(payload, publicKey); err != nil {
		return err
	}

	// verify token claims
	if err := token.verifyClaims(); err != nil {
		return err
	}

	// proof-of-possession
	tp, err := getThumbprintFromTLSState(state)
	if err != nil {
		return err
	}
	if err := token.verifyPoP(tp); err != nil {
		return err
	}
	return nil
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
