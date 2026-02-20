// Package worker re-exports auth system workers
package worker

import iworker "github.com/arpansaha13/goauthkit/internal/worker"

// Interfaces
type EmailProvider = iworker.EmailProvider

// Worker implementations
type EmailWorkerPool = iworker.EmailWorkerPool
type MockEmailProvider = iworker.MockEmailProvider
type SMTPEmailProvider = iworker.SMTPEmailProvider

// Constructors
func NewEmailWorkerPool(poolSize, queueSize int, provider EmailProvider) *iworker.EmailWorkerPool {
	return iworker.NewEmailWorkerPool(poolSize, queueSize, provider)
}

func NewMockEmailProvider() EmailProvider {
	return iworker.NewMockEmailProvider()
}

func NewSMTPEmailProvider(host string, port int, user, password, from string) EmailProvider {
	return iworker.NewSMTPEmailProvider(host, port, user, password, from)
}
