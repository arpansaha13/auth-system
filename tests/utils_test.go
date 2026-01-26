package tests

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"gorm.io/gorm"

	"github.com/arpansaha13/auth-system/pb"
)

// TableDrivenTestCase represents a single test case in table-driven tests for auth-system
type TableDrivenTestCase struct {
	Name        string
	Setup       func(*TestFixture) error // Setup creates test data
	Test        func(*TestFixture) error // Test executes the test logic
	Verify      func(*TestFixture) error // Verify checks the results (optional)
	ExpectError bool                     // ExpectError indicates if an error is expected
	ErrMsg      string                   // ErrMsg is the expected error message (optional)
}

// TestFixture provides a unified fixture for auth-system tests (gRPC-based)
type TestFixture struct {
	T          *testing.T
	Ctx        context.Context
	GRPCClient pb.AuthServiceClient
	GRPCConn   *grpc.ClientConn
	TestDB     *TestDB
}

// TestDB holds database resources for tests (deprecated, use shared global)
type TestDB struct {
	DB  *gorm.DB
	Ctx context.Context
}

// NewTestFixture creates a new test fixture using global test infrastructure
func NewTestFixture(t *testing.T) *TestFixture {
	testdb := CreateTestDB(t)
	fixture := &TestFixture{
		T:          t,
		Ctx:        testdb.Ctx,
		GRPCClient: GetGRPCClient(),
		GRPCConn:   globalGRPCConn,
		TestDB:     testdb,
	}
	return fixture
}

// Setup cleans up database for fresh test state
func (f *TestFixture) Setup() {
	CleanupTables(f.T)
}
