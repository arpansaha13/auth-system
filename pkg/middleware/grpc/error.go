package grpc

import (
	"google.golang.org/grpc"

	imw "github.com/arpansaha13/goauthkit/internal/middleware"
)

func ErrorInterceptor() grpc.UnaryServerInterceptor {
	return imw.ErrorInterceptor()
}
