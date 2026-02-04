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
	Suite      *BaseTestSuite // Reference to the suite for accessing resources
}

// TestDB holds database resources for tests
type TestDB struct {
	DB  *gorm.DB
	Ctx context.Context
}

// NewTestFixture creates a new test fixture using suite test infrastructure
func NewTestFixture(t *testing.T) *TestFixture {
	// Try to extract the suite from the test context
	// This is a fallback approach - ideally the suite would pass itself
	fixture := &TestFixture{
		T:   t,
		Ctx: context.Background(),
	}
	return fixture
}

// NewTestFixtureWithSuite creates a test fixture with direct suite resources
// Accepts AuthTestSuite, UserTestSuite, AuthE2ETestSuite (or other types that embed BaseTestSuite)
func NewTestFixtureWithSuite(s interface{}) *TestFixture {
	// Type assert to get BaseTestSuite pointer
	var base *BaseTestSuite

	// Try different embedded types
	switch suite := s.(type) {
	case *AuthTestSuite:
		base = &suite.BaseTestSuite
	case *UserTestSuite:
		base = &suite.BaseTestSuite
	case *AuthE2ETestSuite:
		base = &suite.BaseTestSuite
	case *BaseTestSuite:
		base = suite
	default:
		// Fallback for future test suites that embed BaseTestSuite
		// Try to reflect and get the BaseTestSuite field
		return &TestFixture{
			T:   nil,
			Ctx: context.Background(),
		}
	}

	fixture := &TestFixture{
		T:          base.T(),
		Ctx:        base.Ctx,
		GRPCClient: base.GRPCClient,
		GRPCConn:   base.GRPCConn,
		Suite:      base,
		TestDB: &TestDB{
			DB:  base.DB,
			Ctx: base.Ctx,
		},
	}
	return fixture
}

// Setup cleans up database for fresh test state
func (f *TestFixture) Setup() {
	// Cleanup is handled by the suite's SetupTest()
}
