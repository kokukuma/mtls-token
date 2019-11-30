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
	switch name {
	case "HS256":
		return HS256{}, nil
	case "RS256":
		return RS256{}, nil
	default:
		return nil, errors.New("Unsupported error")
	}
}
