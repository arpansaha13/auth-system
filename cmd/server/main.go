package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/arpansaha13/auth-system/internal/config"
	"github.com/arpansaha13/auth-system/internal/controller"
	"github.com/arpansaha13/auth-system/internal/middleware"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
	"github.com/arpansaha13/auth-system/pb"
)

var (
	environment = flag.String("env", "development", "Environment: development, staging, production")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Starting auth service in %s environment", cfg.Environment)

	// Initialize database
	db, err := utils.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := utils.CloseDB(db); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	otpRepo := repository.NewOTPRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	// Initialize email provider
	var emailProvider worker.EmailProvider
	if cfg.Environment == "production" {
		emailProvider = worker.NewSMTPEmailProvider(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPUser,
			cfg.SMTPPassword,
			cfg.EmailFrom,
		)
	} else {
		emailProvider = worker.NewMockEmailProvider()
	}

	// Initialize password hasher and validator
	hasher := utils.NewPasswordHasher()
	validator := utils.NewValidator()

	// Initialize email worker pool
	emailPool := worker.NewEmailWorkerPool(
		cfg.EmailWorkerPoolSize,
		cfg.EmailTaskQueueSize,
		emailProvider,
	)
	defer emailPool.Stop()

	// Initialize auth service
	authService := service.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
		validator,
		service.AuthServiceConfig{
			OTPExpiry:  cfg.OTPExpiry,
			OTPLength:  cfg.OTPLength,
			SessionTTL: cfg.SessionTTL,
			SecretKey:  cfg.SecretKey,
			EmailPool:  emailPool,
		},
	)
	defer emailPool.Stop()

	// Initialize cleanup worker
	cleanupWorker := worker.NewCleanupWorker(
		sessionRepo,
		otpRepo,
		cfg.SessionCleanupInterval,
	)
	cleanupWorker.Start()
	defer cleanupWorker.Stop()

	// Initialize gRPC server
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(middleware.ChainUnaryInterceptors(
			middleware.ErrorInterceptor(),
			middleware.RecoveryInterceptor(),
			middleware.LoggingInterceptor(),
			middleware.AuthorizationInterceptor(),
		)),
	)

	// Register auth service
	authServiceImpl := controller.NewAuthServiceImpl(authService)
	pb.RegisterAuthServiceServer(grpcServer, authServiceImpl)

	// Listen on port
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%s", cfg.GRPCHost, cfg.GRPCPort))
	if err != nil {
		log.Fatalf("Failed to listen on %s:%s: %v", cfg.GRPCHost, cfg.GRPCPort, err)
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting gRPC server on %s:%s", cfg.GRPCHost, cfg.GRPCPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server error: %v", err)
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	<-sigChan
	log.Println("Shutdown signal received, gracefully shutting down...")

	grpcServer.GracefulStop()
	log.Println("gRPC server stopped")
}
