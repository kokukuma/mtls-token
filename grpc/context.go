package grpc

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"
)

// You should use Authorization header to access resource server.
// But I'm not going to force it.
const (
	clientAuthKey = "authorization"
)

// GetTokenFromContext returns token on Authorization header.
func GetTokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no client auth token")
	}

	values, ok := md[clientAuthKey]
	if !ok {
		return "", fmt.Errorf("no client auth token")
	}

	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid client auth format")
	}

	if strings.ToUpper(parts[0]) != "POP" {
		return "", fmt.Errorf("token_type should be POP: %q", parts[0])
	}
	return parts[1], nil
}

// AddTokenToContext returns context that has token.
func AddTokenToContext(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, clientAuthKey, "POP "+token)
}
