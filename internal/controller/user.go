package controller

import (
	"context"
	"log"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GetUser retrieves user information by user ID
func (s *AuthServiceImpl) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	// Validate request
	if err := validateGetUserRequest(req); err != nil {
		log.Printf("get user validation error: %v", err)
		return nil, err
	}

	// Call service
	serviceReq := service.GetUserRequest{
		UserID: req.UserId,
	}

	resp, err := s.authService.GetUser(ctx, serviceReq)
	if err != nil {
		log.Printf("get user error: %v", err)
		return nil, err
	}

	return &pb.GetUserResponse{
		User: &pb.UserData{
			UserId:    resp.User.UserID,
			Email:     resp.User.Email,
			Username:  resp.User.Username,
			Verified:  resp.User.Verified,
			CreatedAt: timestamppb.New(resp.User.CreatedAt),
		},
	}, nil
}

// GetUserByEmail retrieves user information by email address
func (s *AuthServiceImpl) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailRequest) (*pb.GetUserByEmailResponse, error) {
	// Validate request
	if err := validateGetUserByEmailRequest(req); err != nil {
		log.Printf("get user by email validation error: %v", err)
		return nil, err
	}

	// Call service
	serviceReq := service.GetUserByEmailRequest{
		Email: req.Email,
	}

	resp, err := s.authService.GetUserByEmail(ctx, serviceReq)
	if err != nil {
		log.Printf("get user by email error: %v", err)
		return nil, err
	}

	return &pb.GetUserByEmailResponse{
		User: &pb.UserData{
			UserId:    resp.User.UserID,
			Email:     resp.User.Email,
			Username:  resp.User.Username,
			Verified:  resp.User.Verified,
			CreatedAt: timestamppb.New(resp.User.CreatedAt),
		},
	}, nil
}

// DeleteUser deletes a user by user ID
func (s *AuthServiceImpl) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	// Validate request
	if err := validateDeleteUserRequest(req); err != nil {
		log.Printf("delete user validation error: %v", err)
		return nil, err
	}

	// Call service
	serviceReq := service.DeleteUserRequest{
		UserID: req.UserId,
	}

	resp, err := s.authService.DeleteUser(ctx, serviceReq)
	if err != nil {
		log.Printf("delete user error: %v", err)
		return nil, err
	}

	return &pb.DeleteUserResponse{
		Message: resp.Message,
	}, nil
}

// Private helper and validation functions

func validateGetUserRequest(req *pb.GetUserRequest) error {
	if req.UserId <= 0 {
		return &domain.ValidationError{Message: "user_id must be greater than zero", Field: "user_id"}
	}
	return nil
}

func validateGetUserByEmailRequest(req *pb.GetUserByEmailRequest) error {
	if req.Email == "" {
		return &domain.ValidationError{Message: "email is required", Field: "email"}
	}
	return nil
}

func validateDeleteUserRequest(req *pb.DeleteUserRequest) error {
	if req.UserId <= 0 {
		return &domain.ValidationError{Message: "user_id must be greater than zero", Field: "user_id"}
	}
	return nil
}
