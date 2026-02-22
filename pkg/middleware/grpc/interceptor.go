package grpc

import (
	"google.golang.org/grpc"

	imw "github.com/arpansaha13/goauthkit/internal/middleware"
)

// RecoveryInterceptor recovers from panics in gRPC handlers and logs them with context
func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return imw.RecoveryInterceptor()
}
