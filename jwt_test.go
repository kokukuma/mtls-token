package auth

import (
	"reflect"
	"testing"
)

func TestNewJWT(t *testing.T) {
	header := RawHeader{
		"kid": "kid",
	}
	claims := RawClaims{
		"iss": "iss",
	}

	jwt := NewJWT(header, claims)
	if jwt == nil {
		t.Errorf("jwt must be gotten")
	}
}

func TestEncoding(t *testing.T) {
	tcs := map[string]struct {
		header RawHeader
		claims RawClaims
		expect string
	}{
		"empty": {
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{"iss": "iss"},
			expect: "eyJraWQiOiJraWQifQ.eyJpc3MiOiJpc3MifQ",
		},
		"multi claims": {
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{"iss": "iss", "aud": "aud"},
			expect: "eyJraWQiOiJraWQifQ.eyJhdWQiOiJhdWQiLCJpc3MiOiJpc3MifQ",
		},
		"with sharp": {
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{
				"x5t": map[string]interface{}{
					"S256": "hash",
				},
			},
			expect: "eyJraWQiOiJraWQifQ.eyJ4NXQiOnsiUzI1NiI6Imhhc2gifX0",
		},
	}

	for name, tc := range tcs {
		jwt := NewJWT(tc.header, tc.claims)
		actual, err := jwt.Encoding()
		if err != nil {
			t.Errorf("Unexpected error occur: expect:%#v", err)
		}
		if tc.expect != actual {
			t.Errorf("Encoding failed: %s: expect:%#v, given:%#v", name, tc.expect, actual)
		}
	}
}

func TestParse(t *testing.T) {
	tcs := map[string]struct {
		jwt    string
		header RawHeader
		claims RawClaims
	}{
		"normal": {
			jwt:    "eyJraWQiOiJraWQifQ.eyJpc3MiOiJpc3MifQ",
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{"iss": "iss"},
		},
		"multi claims": {
			jwt:    "eyJraWQiOiJraWQifQ.eyJhdWQiOiJhdWQiLCJpc3MiOiJpc3MifQ",
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{"iss": "iss", "aud": "aud"},
		},
		"with sharp": {
			jwt:    "eyJraWQiOiJraWQifQ.eyJ4NXQiOnsiUzI1NiI6Imhhc2gifX0",
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{
				"x5t": map[string]interface{}{
					"S256": "hash",
				},
			},
		},
	}

	for name, tc := range tcs {
		jwt, err := Parse(tc.jwt)
		if err != nil {
			t.Fatalf("Unexpected error occur: expect:%#v", err)
		}
		if !reflect.DeepEqual(jwt.header, tc.header) {
			t.Errorf("Encoding failed: %s: expect:%#v, given:%#v", name, tc.header, jwt.header)
		}
		if !reflect.DeepEqual(jwt.claims, tc.claims) {
			t.Errorf("Encoding failed: %s: expect:%#v, given:%#v", name, tc.claims, jwt.claims)
		}
	}
}