package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"

	mtoken "github.com/kokukuma/mtls-token"
	mtoken_http "github.com/kokukuma/mtls-token/http"
)

func main() {
	// sample private/public key
	privKey, pubKey := creteSampleKey()

	// server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := mtoken.RawClaims{
			"kid": "kokukuma",
		}

		tokenStr, err := mtoken_http.IssueToken(r, privKey, claims)
		if err != nil {
			log.Println(err)
		}
		w.Write([]byte(tokenStr))
	}))
	server.TLS = getTLSServerConfig()
	server.StartTLS()
	defer server.Close()

	// client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: getTLSClientConfig(),
		},
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		log.Fatalf("Failed to get URL: %v", err)
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	tokenStr := string(b)
	fmt.Println(tokenStr)

	jwt, err := mtoken_http.DecodeToken(resp, tokenStr, pubKey)
	if err != nil {
		log.Fatalf("%s", err)
	}
	fmt.Println(jwt)
}

func getTLSServerConfig() *tls.Config {
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err != nil {
		log.Fatal("failed to load keypair")
	}
	if err != nil {
		log.Fatal("failed to load keypair")
	}

	return &tls.Config{
		//ClientAuth:   tls.NoClientCert,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    getCertPool(),
	}
}

func getTLSClientConfig() *tls.Config {
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err != nil {
		log.Fatal("failed to load keypair")
	}

	return &tls.Config{
		ServerName:   "kokukuma.service1.com",
		Certificates: []tls.Certificate{cert},
		RootCAs:      getCertPool(),
	}
}

func getCertPool() *x509.CertPool {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCACert))
	if !ok {
		log.Fatal("failed to append cert to pool")
	}
	return certPool
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
