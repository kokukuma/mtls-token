package mtoken

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// ReadPublicKey return public key.
func ReadPublicKey(path string) (interface{}, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return GetPublicKey(bytes)
}

// GetPublicKey return public key.
// Certificate and Publickey can be parsed.
func GetPublicKey(bytes []byte) (interface{}, error) {
	block, _ := pem.Decode(bytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		return cert.PublicKey, nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ReadPrivateKey returns privatekey.
func ReadPrivateKey(path string) (interface{}, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return GetPrivateKey(bytes)
}

// GetPrivateKey returns privatekey.
// *ecdsa.PrivateKey and *rsa.PrivateKey are supported.
func GetPrivateKey(bytes []byte) (interface{}, error) {
	block, _ := pem.Decode(bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch key := key.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
	}
}
