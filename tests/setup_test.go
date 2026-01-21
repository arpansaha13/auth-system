package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/arpansaha13/auth-system/internal/controller"
	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/middleware"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
	"github.com/arpansaha13/auth-system/pb"
)

var (
	globalContainer    testcontainers.Container
	globalDB           *gorm.DB
	globalCtx          context.Context
	globalGRPCClient   pb.AuthServiceClient
	globalGRPCConn     *grpc.ClientConn
	globalGRPCListener net.Listener
	globalGRPCServer   *grpc.Server
)

// TestMain sets up shared database for all tests
func TestMain(m *testing.M) {
	ctx := context.Background()
	globalCtx = ctx

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "test_auth",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Printf("Failed to start container: %v\n", err)
		return
	}

	globalContainer = container

	// Get container host and port
	host, err := container.Host(ctx)
	if err != nil {
		fmt.Printf("Failed to get host: %v\n", err)
		globalContainer.Terminate(ctx)
		return
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		fmt.Printf("Failed to get port: %v\n", err)
		globalContainer.Terminate(ctx)
		return
	}

	// Connect to database
	dsn := fmt.Sprintf(
		"host=%s port=%s user=testuser password=testpass dbname=test_auth sslmode=disable",
		host, port.Port(),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		globalContainer.Terminate(ctx)
		return
	}

	globalDB = db

	// Run migrations
	if err := domain.AutoMigrate(db); err != nil {
		fmt.Printf("Failed to run migrations: %v\n", err)
		globalContainer.Terminate(ctx)
		os.Exit(1)
	}

	// Setup gRPC server
	if err := setupGRPCServer(db); err != nil {
		fmt.Printf("Failed to setup gRPC server: %v\n", err)
		globalContainer.Terminate(ctx)
		os.Exit(1)
	}

	code := m.Run()

	// Cleanup
	globalGRPCServer.Stop()
	globalGRPCConn.Close()
	globalContainer.Terminate(ctx)
	os.Exit(code)
}

// setupGRPCServer sets up the gRPC server with interceptors and client
func setupGRPCServer(db *gorm.DB) error {
	var err error

	// Create listener
	globalGRPCListener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	// Import necessary packages for server setup
	// Create gRPC server with interceptors
	globalGRPCServer = grpc.NewServer(
		grpc.UnaryInterceptor(middleware.ChainUnaryInterceptors(
			middleware.RecoveryInterceptor(),
			middleware.LoggingInterceptor(),
			middleware.AuthorizationInterceptor(),
		)),
	)

	// Register auth service
	userRepo := repository.NewUserRepository(db)
	otpRepo := repository.NewOTPRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	hasher := utils.NewPasswordHasher()
	validator := utils.NewValidator()
	emailProvider := worker.NewMockEmailProvider()
	emailPool := worker.NewEmailWorkerPool(2, 50, emailProvider)

	authService := service.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
		validator,
		service.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
			EmailPool:  emailPool,
		},
	)

	authServiceImpl := controller.NewAuthServiceImpl(authService)
	pb.RegisterAuthServiceServer(globalGRPCServer, authServiceImpl)

	// Start server in goroutine
	go func() {
		if err := globalGRPCServer.Serve(globalGRPCListener); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	// Create client
	conn, err := grpc.Dial(
		globalGRPCListener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	globalGRPCConn = conn
	globalGRPCClient = pb.NewAuthServiceClient(conn)

	return nil
}

func exit(code int) {
	globalContainer.Terminate(globalCtx)
	testingExit(code)
}

// testingExit will be replaced in tests
var testingExit = func(code int) {
	os.Exit(code)
}

// GetTestDB returns the global test database
func GetTestDB() *gorm.DB {
	return globalDB
}

// GetTestContext returns the global test context
func GetTestContext() context.Context {
	return globalCtx
}

// GetGRPCClient returns the global gRPC client
func GetGRPCClient() pb.AuthServiceClient {
	return globalGRPCClient
}

// CleanupTables truncates all tables to ensure test isolation
func CleanupTables(t *testing.T) {
	tables := []string{"sessions", "otps", "credentials", "users"}

	for _, table := range tables {
		if err := globalDB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error; err != nil {
			t.Fatalf("Failed to truncate table %s: %v", table, err)
		}
	}
}
