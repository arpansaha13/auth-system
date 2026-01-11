package worker

import (
	"context"
	"log"
	"time"

	"github.com/arpansaha13/auth-system/internal/repository"
)

// CleanupWorker handles periodic cleanup tasks
type CleanupWorker struct {
	sessionRepo *repository.SessionRepository
	otpRepo     *repository.OTPRepository
	interval    time.Duration
	stopChan    chan bool
}

// NewCleanupWorker creates a new cleanup worker
func NewCleanupWorker(
	sessionRepo *repository.SessionRepository,
	otpRepo *repository.OTPRepository,
	interval time.Duration,
) *CleanupWorker {
	return &CleanupWorker{
		sessionRepo: sessionRepo,
		otpRepo:     otpRepo,
		interval:    interval,
		stopChan:    make(chan bool),
	}
}

// Start starts the cleanup worker
func (w *CleanupWorker) Start() {
	log.Printf("starting cleanup worker with interval: %v", w.interval)

	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				w.cleanup()
			case <-w.stopChan:
				log.Println("stopping cleanup worker")
				return
			}
		}
	}()
}

// Stop stops the cleanup worker
func (w *CleanupWorker) Stop() {
	w.stopChan <- true
}

// cleanup removes expired sessions and OTPs
func (w *CleanupWorker) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Clean up expired sessions
	if err := w.sessionRepo.DeleteExpiredAndSoftDeleted(ctx); err != nil {
		log.Printf("failed to delete expired sessions: %v", err)
	} else {
		log.Println("expired sessions cleaned up")
	}

	// Clean up expired OTPs
	if err := w.otpRepo.DeleteExpiredAndSoftDeleted(ctx); err != nil {
		log.Printf("failed to delete expired otps: %v", err)
	} else {
		log.Println("expired otps cleaned up")
	}
}
