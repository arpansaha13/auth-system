package middleware

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/arpansaha13/goauthkit/internal/domain"
)

// MockHandler creates a mock gRPC handler that returns the specified error
func mockHandler(returnErr error) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		if returnErr != nil {
			return nil, returnErr
		}
		return "success", nil
	}
}

// TestErrorInterceptor_ValidationError tests that ValidationError is converted to InvalidArgument
func TestErrorInterceptor_ValidationError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(&domain.ValidationError{
		Message: "email is required",
		Field:   "email",
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/Signup"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "email is required")
}

// TestErrorInterceptor_ConflictError tests that ConflictError is converted to AlreadyExists
func TestErrorInterceptor_ConflictError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(&domain.ConflictError{
		Message: "email already registered",
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/Signup"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Contains(t, err.Error(), "email already registered")
}

// TestErrorInterceptor_NotFoundError tests that NotFoundError is converted to NotFound
func TestErrorInterceptor_NotFoundError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(&domain.NotFoundError{
		Message: "user not found",
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/GetUser"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Contains(t, err.Error(), "user not found")
}

// TestErrorInterceptor_UnauthorizedError tests that UnauthorizedError is converted to Unauthenticated
func TestErrorInterceptor_UnauthorizedError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(&domain.UnauthorizedError{
		Message: "invalid credentials",
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/Login"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "invalid credentials")
}

// TestErrorInterceptor_InternalError tests that InternalError is converted to Internal
func TestErrorInterceptor_InternalError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(&domain.InternalError{
		Message: "database connection failed",
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/Signup"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "internal server error")
}

// TestErrorInterceptor_GenericError tests that generic errors are converted to Internal
func TestErrorInterceptor_GenericError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(fmt.Errorf("unknown error"))
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/Signup"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), "internal server error")
}

// TestErrorInterceptor_NoError tests that successful responses pass through unchanged
func TestErrorInterceptor_NoError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/Signup"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.NoError(t, err)
	assert.Equal(t, "success", resp)
}

// TestErrorInterceptor_NilError tests that nil errors are handled correctly
func TestErrorInterceptor_NilError(t *testing.T) {
	interceptor := ErrorInterceptor()
	handler := mockHandler(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/proto.AuthService/GetUser"}

	resp, err := interceptor(context.Background(), nil, info, handler)

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestErrorToGRPCError_ValidationError tests the direct translation function
func TestErrorToGRPCError_ValidationError(t *testing.T) {
	err := &domain.ValidationError{
		Message: "email is required",
		Field:   "email",
	}

	result := errorToGRPCError(err)

	require.Error(t, result)
	assert.Equal(t, codes.InvalidArgument, status.Code(result))
}

// TestErrorToGRPCError_ConflictError tests the direct translation function
func TestErrorToGRPCError_ConflictError(t *testing.T) {
	err := &domain.ConflictError{
		Message: "email already exists",
	}

	result := errorToGRPCError(err)

	require.Error(t, result)
	assert.Equal(t, codes.AlreadyExists, status.Code(result))
}

// TestErrorToGRPCError_NotFoundError tests the direct translation function
func TestErrorToGRPCError_NotFoundError(t *testing.T) {
	err := &domain.NotFoundError{
		Message: "user not found",
	}

	result := errorToGRPCError(err)

	require.Error(t, result)
	assert.Equal(t, codes.NotFound, status.Code(result))
}

// TestErrorToGRPCError_UnauthorizedError tests the direct translation function
func TestErrorToGRPCError_UnauthorizedError(t *testing.T) {
	err := &domain.UnauthorizedError{
		Message: "invalid token",
	}

	result := errorToGRPCError(err)

	require.Error(t, result)
	assert.Equal(t, codes.Unauthenticated, status.Code(result))
}

// TestErrorToGRPCError_UnknownError tests the direct translation function
func TestErrorToGRPCError_UnknownError(t *testing.T) {
	err := fmt.Errorf("some unknown error")

	result := errorToGRPCError(err)

	require.Error(t, result)
	assert.Equal(t, codes.Internal, status.Code(result))
}

// TestErrorToGRPCError_NilError tests the direct translation function
func TestErrorToGRPCError_NilError(t *testing.T) {
	result := errorToGRPCError(nil)

	assert.NoError(t, result)
	assert.Nil(t, result)
}
