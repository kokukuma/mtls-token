package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"

	mtoken "github.com/kokukuma/mtls-token"
	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	mook_conn "github.com/theshadow/mock-conn"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type customToken struct {
	mtoken.Token
	ClientID string   `json:"client_id"`
	DNSName  string   `json:"dns_name"`
	Test     []string `json:"test"`
}

func main() {
	// sample private/public key
	privKey, pubKey := creteSampleKey()

	// Just create mock of ctx used in TLS connection
	ctx := createSampleTLSContext()

	// create token struct
	token := &customToken{
		Token: mtoken.Token{
			Kid: "kokukuma",
			Iss: "kokukuma",
		},
		ClientID: "3",
		DNSName:  "kokukuma.com",
		Test:     []string{"kokuban", "kumasan"},
	}
	fmt.Println(token)

	// create token string
	tokenStr, err := mtoken_grpc.IssueToken(ctx, privKey, token)
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println(tokenStr)

	// verify and decode token struct from token string
	verifiedToken := &customToken{}
	err = mtoken_grpc.DecodeToken(ctx, tokenStr, pubKey, verifiedToken)
	if err != nil {
	}
	fmt.Println(verifiedToken)
}

func createSampleTLSContext() context.Context {
	conn := mook_conn.NewConn()
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: conn.LocalAddr(),
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					&x509.Certificate{
						PublicKey: &rsa.PublicKey{
							N: big.NewInt(12),
							E: 1,
						},
					},
				},
			},
		},
	})
	return ctx
}

func creteSampleKey() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("%v", err)
	}
	p := privKey.Public()
	pubKey, ok := p.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("failed to convert rsa")
	}
	return privKey, pubKey
}
