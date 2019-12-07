package mtoken

import (
	"testing"
)

func TestHS256SignVerifySuccess(t *testing.T) {
	secret := []byte("secret")

	tcs := map[string]struct {
		contents string
	}{
		"empty": {
			contents: "sample",
		},
	}

	for name, tc := range tcs {
		rs := HS256{}
		sign, err := rs.Sign(secret, tc.contents)
		if err != nil {
			t.Fatalf("Unexpected error occur in %s: expect:%#v", name, err)
		}

		err = rs.Verify(secret, tc.contents, sign)
		if err != nil {
			t.Fatalf("Unexpected error occur in %s: expect:%#v", name, err)
		}
	}
}

func TestHS256SignFailed(t *testing.T) {
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
		rs := HS256{}
		_, err := rs.Sign(tc.privKey, tc.contents)
		if err == nil {
			t.Fatalf("Should be error occur in %s", name)
		}
		if err.Error() != tc.err {
			t.Errorf("Unexpeccted error occur: %s: expect:%#v, given:%#v", name, tc.err, err.Error())
		}
	}
}
