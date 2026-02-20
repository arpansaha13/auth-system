package grpc

import (
	"google.golang.org/grpc"

	imw "github.com/arpansaha13/auth-system/internal/middleware"
)

func ErrorInterceptor() grpc.UnaryServerInterceptor {
	return imw.ErrorInterceptor()
}
