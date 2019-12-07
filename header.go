package mtoken

import "errors"

// RawHeader is the header of JWT
type RawHeader map[string]interface{}

// GetString returns value as string related to the key.
func (r RawHeader) GetString(key string) (string, error) {
	if _, ok := r[key]; !ok {
		return "", errors.New("key is not found in header")
	}
	if v, ok := r[key].(string); ok {
		return v, nil
	}
	return "", errors.New("type is not much")
}
