package auth

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNewJWT(t *testing.T) {
	header := RawHeader{
		"kid": "kid",
	}
	claims := RawClaims{
		"iss": "iss",
	}

	jwt := NewJWT(header, claims, RS256{})
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
			expect: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJpc3MiOiJpc3MifQ",
		},
		"multi claims": {
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{"iss": "iss", "aud": "aud"},
			expect: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJhdWQiOiJhdWQiLCJpc3MiOiJpc3MifQ",
		},
		"with sharp": {
			header: RawHeader{"kid": "kid"},
			claims: RawClaims{
				"cnf": map[string]interface{}{
					"x5t#S256": "hash",
				},
			},
			expect: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJjbmYiOnsieDV0I1MyNTYiOiJoYXNoIn19",
		},
	}

	for name, tc := range tcs {
		jwt := NewJWT(tc.header, tc.claims, RS256{})
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
		"hs256": {
			jwt:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJpc3MiOiJpc3MifQ",
			header: RawHeader{"alg": "RS256", "kid": "kid"},
			claims: RawClaims{"iss": "iss"},
		},
		"rs256": {
			jwt:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJpc3MiOiJpc3MifQ",
			header: RawHeader{"alg": "RS256", "kid": "kid"},
			claims: RawClaims{"iss": "iss"},
		},
		"multi claims": {
			jwt:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJhdWQiOiJhdWQiLCJpc3MiOiJpc3MifQ",
			header: RawHeader{"alg": "RS256", "kid": "kid"},
			claims: RawClaims{"iss": "iss", "aud": "aud"},
		},
		"with sharp": {
			jwt:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJjbmYiOnsieDV0I1MyNTYiOiJoYXNoIn19",
			header: RawHeader{"alg": "RS256", "kid": "kid"},
			claims: RawClaims{
				"cnf": map[string]interface{}{
					"x5t#S256": "hash",
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

func TestDefaultClaims(t *testing.T) {
	tcs := map[string]struct {
		input  RawClaims
		output RawClaims
	}{
		"normal": {
			input:  RawClaims{"iss": "iss"},
			output: RawClaims{"exp": int64(1521648467), "iat": int64(1521644867), "iss": "iss"},
		},
		"set exp": {
			input:  RawClaims{"iss": "iss", "exp": int64(1)},
			output: RawClaims{"exp": int64(1), "iat": int64(1521644867), "iss": "iss"},
		},
		"set iat": {
			input:  RawClaims{"iss": "iss", "iat": int64(1)},
			output: RawClaims{"exp": int64(3601), "iat": int64(1), "iss": "iss"},
		},
	}

	timeFunc = func() time.Time {
		return time.Unix(1521644867, 0)
	}

	for name, tc := range tcs {
		actual := addTimeClaims(tc.input)
		if !reflect.DeepEqual(actual, tc.output) {
			t.Errorf("Unexpected output: %s: expect:%#v, given:%#v", name, tc.output, actual)
		}
	}
}

func TestAddX5tS256(t *testing.T) {
	tcs := map[string]struct {
		input  RawClaims
		output RawClaims
		err    error
	}{
		"normal": {
			input: RawClaims{"iss": "iss"},
			output: RawClaims{"iss": "iss", "cnf": map[string]interface{}{
				"x5t#S256": "thumbprint",
			}},
		},
		"set x5t#S256": {
			input: RawClaims{"iss": "iss", "cnf": map[string]interface{}{
				"x5t#S256": "thumbprint2",
			}},
			output: RawClaims{"iss": "iss", "cnf": map[string]interface{}{
				"x5t#S256": "thumbprint2",
			}},
		},
		"set x5t": {
			input: RawClaims{"iss": "iss", "cnf": map[string]interface{}{
				"test": "test",
			}},
			output: RawClaims{"iss": "iss", "cnf": map[string]interface{}{
				"x5t#S256": "thumbprint",
				"test":     "test",
			}},
		},
		"set other type x5t": {
			input: RawClaims{"iss": "iss", "cnf": map[string]string{
				"x5t#S256": "thumbprint2",
			}},
			output: RawClaims{"iss": "iss", "cnf": map[string]interface{}{
				"x5t#S256": "thumbprint2",
			}},
			err: errors.New("cnf must be map[string]interface{}"),
		},
	}

	for name, tc := range tcs {
		actual, err := addX5tS256(tc.input, "thumbprint")
		if tc.err != nil || err != nil {
			if !reflect.DeepEqual(tc.err, err) {
				t.Errorf("Unexpected output: %s: expect:%#v, given:%#v", name, tc.err, err)
			}
			continue
		}
		if !reflect.DeepEqual(actual, tc.output) {
			t.Errorf("Unexpected output: %s: expect:%#v, given:%#v", name, tc.output, actual)
		}
	}
}
