package auth

import "errors"

// Method is interface for jwt signature.
type Method interface {
	Name() string
	Sign(interface{}, string) ([]byte, error)
	Verify(interface{}, string, []byte) error
}

// ParseMethod convert alg name to method.
func ParseMethod(name string) (Method, error) {
	if name == "RS256" {
		return RS256{}, nil
	}
	return nil, errors.New("Unsupported error")
}
