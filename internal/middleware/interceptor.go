package middleware

import (
	"context"
	"log"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthorizationInterceptor intercepts gRPC requests to validate session tokens
func AuthorizationInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authorization for public endpoints
		if isPublicEndpoint(info.FullMethod) {
			return handler(ctx, req)
		}

		// Extract token from metadata
		token := extractTokenFromMetadata(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid authorization token")
		}

		// Add token to context
		ctx = context.WithValue(ctx, "authorization", token)

		// Continue with handler
		return handler(ctx, req)
	}
}

// RecoveryInterceptor recovers from panics in gRPC handlers
func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic recovered in %s: %v", info.FullMethod, r)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// LoggingInterceptor logs gRPC method calls
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		log.Printf("gRPC method called: %s", info.FullMethod)

		resp, err := handler(ctx, req)

		if err != nil {
			log.Printf("gRPC method %s returned error: %v", info.FullMethod, err)
		}

		return resp, err
	}
}

// Private helper functions

func extractTokenFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}

	// Extract bearer token
	authHeader := values[0]
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return authHeader
}

func isPublicEndpoint(fullMethod string) bool {
	publicEndpoints := map[string]bool{
		"/auth.AuthService/Signup":   true,
		"/auth.AuthService/Login":    true,
		"/auth.AuthService/VerifyOTP": true,
	}

	return publicEndpoints[fullMethod]
}

// ChainUnaryInterceptors chains multiple unary interceptors
func ChainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Build chain from right to left
		for i := len(interceptors) - 1; i >= 0; i-- {
			next := handler
			currentInterceptor := interceptors[i]
			handler = func(ctx context.Context, req interface{}) (interface{}, error) {
				return currentInterceptor(ctx, req, info, next)
			}
		}
		return handler(ctx, req)
	}
}
