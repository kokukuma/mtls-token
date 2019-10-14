package grpc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"

	mtls_token "github.com/kokukuma/mtls-token"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// IssueToken creates access token.
func IssueToken(ctx context.Context, privateKey *rsa.PrivateKey, token mtls_token.Issuer) (string, error) {
	state, err := getCSFromContext(ctx)
	if err != nil {
		return "", err
	}
	return mtls_token.IssueToken(state, privateKey, token)
}

// DecodeToken decode token
func DecodeToken(ctx context.Context, payload string, publicKey *rsa.PublicKey, token mtls_token.Verifyer) error {
	state, err := getCSFromContext(ctx)
	if err != nil {
		return err
	}
	return mtls_token.DecodeToken(state, payload, publicKey, token)
}

func getCSFromContext(ctx context.Context) (*tls.ConnectionState, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("failed to get peer")
	}

	if peer.AuthInfo == nil {
		return nil, errors.New("connection should be used TLS")
	}

	if peer.AuthInfo.AuthType() != "tls" {
		return nil, errors.New("connection should be used TLS")
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("connection should be used TLS")
	}

	return &tlsInfo.State, nil
}
