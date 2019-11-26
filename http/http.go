package http

import (
	"crypto/rsa"
	"errors"
	"net/http"

	mtls_token "github.com/kokukuma/mtls-token"
)

// IssueToken creates access token.
func IssueToken(req *http.Request, privateKey *rsa.PrivateKey, claims mtls_token.RawClaims) (string, error) {
	if req == nil {
		return "", errors.New("http request is nil")
	}
	state := req.TLS
	return mtls_token.IssueToken(state, privateKey, claims)
}

// DecodeToken decode token
func DecodeToken(resp *http.Response, payload string, publicKey *rsa.PublicKey) (*mtls_token.JWT, error) {
	if resp == nil {
		return nil, errors.New("http response is nil")
	}
	state := resp.TLS
	return mtls_token.DecodeToken(state, payload, publicKey)
}
