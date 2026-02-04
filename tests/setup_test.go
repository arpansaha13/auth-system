package tests

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/stretchr/testify/suite"
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

// BaseTestSuite provides common test setup and teardown for all test suites
type BaseTestSuite struct {
	suite.Suite
	Container     testcontainers.Container
	DB            *gorm.DB
	Ctx           context.Context
	GRPCClient    pb.AuthServiceClient
	GRPCConn      *grpc.ClientConn
	GRPCListener  net.Listener
	GRPCServer    *grpc.Server
	AuthService   *service.AuthService
	EmailPool     *worker.EmailWorkerPool
	EmailProvider *worker.MockEmailProvider
}

// SetupSuite initializes the test environment (runs once before all tests)
func (s *BaseTestSuite) SetupSuite() {
	ctx := context.Background()
	s.Ctx = ctx

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
	s.Require().NoError(err, "Failed to start PostgreSQL container")
	s.Container = container

	// Get container host and port
	host, err := container.Host(ctx)
	s.Require().NoError(err, "Failed to get container host")

	port, err := container.MappedPort(ctx, "5432")
	s.Require().NoError(err, "Failed to get container port")

	// Connect to database
	dsn := fmt.Sprintf(
		"host=%s port=%s user=testuser password=testpass dbname=test_auth sslmode=disable",
		host, port.Port(),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	s.Require().NoError(err, "Failed to connect to database")
	s.DB = db

	// Run migrations
	err = domain.AutoMigrate(db)
	s.Require().NoError(err, "Failed to run migrations")

	// Setup gRPC server
	err = s.setupGRPCServer(ctx, db)
	s.Require().NoError(err, "Failed to setup gRPC server")
}

// TearDownSuite cleans up the test environment (runs once after all tests)
func (s *BaseTestSuite) TearDownSuite() {
	if s.GRPCServer != nil {
		s.GRPCServer.Stop()
	}
	if s.GRPCConn != nil {
		s.GRPCConn.Close()
	}
	if s.Container != nil {
		s.Container.Terminate(s.Ctx)
	}
}

// SetupTest prepares each test (cleans tables)
func (s *BaseTestSuite) SetupTest() {
	s.CleanupTablesForSuite()
}

// CleanupTablesForSuite truncates all tables for test isolation
func (s *BaseTestSuite) CleanupTablesForSuite() {
	tables := []string{"sessions", "otps", "credentials", "users"}

	for _, table := range tables {
		err := s.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error
		s.Require().NoError(err, "Failed to truncate table %s", table)
	}
}

// setupGRPCServer sets up the gRPC server with interceptors and client
func (s *BaseTestSuite) setupGRPCServer(ctx context.Context, db *gorm.DB) error {
	var err error

	// Create listener
	s.GRPCListener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	// Create gRPC server with interceptors
	s.GRPCServer = grpc.NewServer(
		grpc.UnaryInterceptor(middleware.ChainUnaryInterceptors(
			middleware.ErrorInterceptor(),
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
	s.EmailProvider = worker.NewMockEmailProvider()
	s.EmailPool = worker.NewEmailWorkerPool(2, 50, s.EmailProvider)

	s.AuthService = service.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
		service.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
			EmailPool:  s.EmailPool,
		},
	)

	authServiceImpl := controller.NewAuthServiceImpl(s.AuthService, validator)
	pb.RegisterAuthServiceServer(s.GRPCServer, authServiceImpl)

	// Start server in goroutine
	go func() {
		if err := s.GRPCServer.Serve(s.GRPCListener); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	// Create client
	conn, err := grpc.Dial(
		s.GRPCListener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	s.GRPCConn = conn
	s.GRPCClient = pb.NewAuthServiceClient(conn)

	return nil
}
