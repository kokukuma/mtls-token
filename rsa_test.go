package auth

import (
	"strings"
	"testing"
)

func getPrivateKey() (interface{}, error) {
	key := testingKey(`-----BEGIN TESTING KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDINZAIq42bDBnT
qsfHhGdMjN5kBYy5Huwixl6tel4Zdyz+5B+j8uIOFGn7qL2y3ak7FS8LynN2SUVO
2qqwz0a5h4v5yeFdSqWFndSf5TFZB4zFfr1Ii6etrr29nA1aEnWdLiBMV6tkMK+f
s/MGp/d4/qvql0Sg1eg6A7e4+w2TuDXd3PIUBxyNw03uogzcRS13jvWZJY5aF3Fp
JpL4xTtFdvyAB8rvOoELx0GMorCc+1WyMlG2Nr+58JV7qG8tzPuWjAWEgOJU4ZE+
LNxN85jUUvN1c1cctKgfon8qfJ/XtkQRC9JRhxXqyGEjU4EAzn1lLCgYGndqYKsc
j+I6q35nAgMBAAECggEBAJUrw3uSRtnlNEEPl/bCYi0ZMIIZ2HX94jcu0lAzQnV6
5F2uHx0K1P9kmmrVmTHyEithZ0JDv6+8fBV6u38tkSafJd4hWvclrRpXNJtGK3SI
OYzVF7c7xt2Tuu/Rm+kmo9dPDOWU1LC7zb8SVtr4v1y5c+JAfvPPLU48guEivUT3
ws5OxvFsm8sQ1MYe+1Ir505MJE35qXgfJBdOAsqonAWgunPc1YPBrNSiIZUPr8W+
IwBcSMjt8DOsu4wZqLPOP6o9/LvGuQe3vBV3AArcwciTvZX8NVv5ih+I/LZNpGPx
OTg09s5qvRG54GvPzKVhX1uLReVckyrP87C0L/W5HzECgYEA+TyMTwJ8QS8Idia4
exhhGM0vYmmxF0gSbY0ESjeZESKb1hop3oniKP2qdgSmW+QqZ921stARfcAcYrRE
bPXmX077r4anCH2aP5vsSBbIJPALy2IEj39L/1EXoPfX2ZjYzBmNTQ9raWv30G/K
5O0Uk/vay5s4vk5fqoW2mEksKUUCgYEAzaRrvC4N8D+C/P0K/+hnr2hJeqjVZ7iQ
2MCT7zoiflfC4D9uajeR/UgiJuTz4sfSNv6GvllFXlHhScTWHdmfOpsaO/UsBTzN
5kSXY8t7Hfe7FPEKtf+e1jPouJnewTmqmRp+TjaeWFO0Vn+sAX7oTjvZmbgPAa6H
6i25JdJfBbsCgYEAxepI2Oz2UqTQqVIyKL3BTPqS6ClZ0U0QJSJYB7+Cs1KyQSBh
ozAHAdn9pN4oZMwYyIYMpUQIv7zwTYks1QGnwINt5YKd3WYwONbOmKhOotZj50uc
p37EkKiKhO6K32Y6skiQJmNaPkrYbRJ5IbUKJEFZC1nlg2mlGjo4N1HT2akCgYBp
O4eKL8MgO1ALqG31kPdmMqbPZxB12GP/F2VcmVJHdx+ZY7xcDH3fsAcSAj2vwnOX
gt5vD/3Ii3wPJPQxKEksU2y0W/0f3QK8oEMcZWdmaXxJ9iN2CQ4+LSgdN1hfZuQf
Hwide6PCLWtujDz4Mvor9sKewCqlwKt6sdU6PpIzuwKBgQDLSiTszfL9LqIUWiyF
1RMAK0sAb6Zxc+8psMDmQvkLnHFoiUK8OEiMfmFvJ8g00yTJezaQZphQMlfkZoRt
fInktH4JRhDV734xexcJwG9ICnii+yWAbGZaEjoPRe4RDQSCtTPzgLe5dC3aagmw
/G1moTcs2zY15OhDnihfJcS8nQ==
-----END TESTING KEY-----`)
	return GetPrivateKey([]byte(key))
}

func getPublicKey() (interface{}, error) {
	key := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyDWQCKuNmwwZ06rHx4Rn
TIzeZAWMuR7sIsZerXpeGXcs/uQfo/LiDhRp+6i9st2pOxUvC8pzdklFTtqqsM9G
uYeL+cnhXUqlhZ3Un+UxWQeMxX69SIunra69vZwNWhJ1nS4gTFerZDCvn7PzBqf3
eP6r6pdEoNXoOgO3uPsNk7g13dzyFAccjcNN7qIM3EUtd471mSWOWhdxaSaS+MU7
RXb8gAfK7zqBC8dBjKKwnPtVsjJRtja/ufCVe6hvLcz7lowFhIDiVOGRPizcTfOY
1FLzdXNXHLSoH6J/Knyf17ZEEQvSUYcV6shhI1OBAM59ZSwoGBp3amCrHI/iOqt+
ZwIDAQAB
-----END PUBLIC KEY-----`
	return GetPublicKey([]byte(key))
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func TestRS256SignVerifySuccess(t *testing.T) {
	priv, err := getPrivateKey()
	if err != nil {
		t.Fatalf("Unexpected error occur: expect:%#v", err)
	}
	pub, err := getPublicKey()
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
		rs := RS256{}
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

func TestRS256SignFailed(t *testing.T) {
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
		rs := RS256{}
		_, err := rs.Sign(tc.privKey, tc.contents)
		if err == nil {
			t.Fatalf("Should be error occur in %s", name)
		}
		if err.Error() != tc.err {
			t.Errorf("Unexpeccted error occur: %s: expect:%#v, given:%#v", name, tc.err, err.Error())
		}
	}
}
