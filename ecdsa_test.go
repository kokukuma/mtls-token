package mtoken

import (
	"testing"
)

func getECDSAPrivateKey() (interface{}, error) {
	key := testingKey(`-----BEGIN TESTING KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbrn0aNIuJ8VJRLlX
voGFsxJezvxnXmylyFQyrU47RhOhRANCAARNJE32mzlLstEsiRsy1ryvLJi/lQZs
nNjKNUIZT6w7ZP3K0AiDkqvGEaw0DMcsGsPAmSctVxiscvNWKrOQN455
-----END TESTING KEY-----`)
	return GetPrivateKey([]byte(key))
}

func getECDSAPublicKey() (interface{}, error) {
	key := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETSRN9ps5S7LRLIkbMta8ryyYv5UG
bJzYyjVCGU+sO2T9ytAIg5KrxhGsNAzHLBrDwJknLVcYrHLzViqzkDeOeQ==
-----END PUBLIC KEY-----`
	return GetPublicKey([]byte(key))
}

func TestES256SignVerifySuccess(t *testing.T) {
	priv, err := getECDSAPrivateKey()
	if err != nil {
		t.Fatalf("Unexpected error occur: expect:%#v", err)
	}
	pub, err := getECDSAPublicKey()
	if err != nil {
		t.Fatalf("Unexpected error occur: expect:%#v", err)
	}

	tcs := map[string]struct {
		contents string
	}{
		"empty": {
			contents: "sample",
		},
	}

	for name, tc := range tcs {
		rs := ES256{}
		sign, err := rs.Sign(priv, tc.contents)
		if err != nil {
			t.Fatalf("Unexpected error occur in %s: expect:%#v", name, err)
		}

		err = rs.Verify(pub, tc.contents, sign)
		if err != nil {
			t.Fatalf("Unexpected error occur in %s: expect:%#v", name, err)
		}
	}
}

func TestES256SignFailed(t *testing.T) {
	tcs := map[string]struct {
		privKey  interface{}
		contents string
		err      string
	}{
		"empty key": {
			privKey:  "",
			contents: "sample",
			err:      "Unexpected key type",
		},
	}

	for name, tc := range tcs {
		rs := ES256{}
		_, err := rs.Sign(tc.privKey, tc.contents)
		if err == nil {
			t.Fatalf("Should be error occur in %s", name)
		}
		if err.Error() != tc.err {
			t.Errorf("Unexpeccted error occur: %s: expect:%#v, given:%#v", name, tc.err, err.Error())
		}
	}
}

func TestPadding(t *testing.T) {
	tcs := map[string]struct {
		b []byte
		l int
		e int
	}{
		"low": {
			b: []byte("abcde"),
			l: 10,
			e: 10,
		},
		"same": {
			b: []byte("abcde"),
			l: 5,
			e: 5,
		},
		"over": {
			b: []byte("abcde"),
			l: 3,
			e: 5,
		},
	}

	for name, tc := range tcs {
		b := padding(tc.b, tc.l)
		if len(b) != tc.e {
			t.Errorf("Unexpeccted length in %s: expect:%#v, given:%#v", name, tc.e, len(b))
		}
	}
}
