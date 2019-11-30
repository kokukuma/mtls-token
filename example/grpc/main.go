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

func main() {
	// sample private/public key
	privKey, pubKey := creteSampleKey()

	// Just create mock of ctx used in TLS connection
	ctx := createSampleTLSContext()

	claims := mtoken.RawClaims{
		"iss":       "kokukuma",
		"client_id": "3",
		"dns_name":  "kokukuma.com",
		"test":      []string{"kokuban", "kumasan"},
	}
	fmt.Println(claims)

	// create token string
	tokenStr, err := mtoken_grpc.IssueToken(ctx, privKey, claims)
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println(tokenStr)

	// verify and decode token struct from token string
	jwt, err := mtoken_grpc.DecodeToken(ctx, tokenStr, pubKey)
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println(jwt)
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
