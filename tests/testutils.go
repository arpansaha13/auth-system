package tests

import "testing"

// TestCase represents a generic test case with setup, request, and validation
type TestCase[Req any, Resp any, SetupReturn any] struct {
	Name        string
	Setup       func(*testing.T) SetupReturn
	GetRequest  func(SetupReturn) Req
	Validate    func(*testing.T, Resp, SetupReturn)
	ExpectError bool
	ErrorType   string
}
