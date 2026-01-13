package tests

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/arpansaha13/auth-system/internal/domain"
)

var (
	globalContainer testcontainers.Container
	globalDB        *gorm.DB
	globalCtx       context.Context
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
		return
	}

	code := m.Run()

	// Cleanup
	globalContainer.Terminate(ctx)
	exit(code)
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

// CleanupTables truncates all tables to ensure test isolation
func CleanupTables(t *testing.T) {
	tables := []string{"sessions", "otps", "credentials", "users"}

	for _, table := range tables {
		if err := globalDB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error; err != nil {
			t.Fatalf("Failed to truncate table %s: %v", table, err)
		}
	}
}
