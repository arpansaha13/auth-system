package worker

import (
	"context"
	"log"
	"sync"
)

// EmailTask represents an email task to be sent
type EmailTask struct {
	Recipient string
	Subject   string
	Body      string
}

// EmailWorkerPool manages a pool of email worker goroutines with a buffered channel
type EmailWorkerPool struct {
	taskQueue     chan EmailTask
	emailProvider EmailProvider
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
}

// EmailProvider interface for sending emails
type EmailProvider interface {
	SendEmail(ctx context.Context, email, subject, body string) error
}

// NewEmailWorkerPool creates a new email worker pool
func NewEmailWorkerPool(workerCount int, queueSize int, emailProvider EmailProvider) *EmailWorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &EmailWorkerPool{
		taskQueue:     make(chan EmailTask, queueSize),
		emailProvider: emailProvider,
		ctx:           ctx,
		cancel:        cancel,
	}

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		pool.wg.Add(1)
		go pool.worker(i)
	}

	log.Printf("email worker pool started with %d workers", workerCount)
	return pool
}

// Stop gracefully stops the worker pool
func (p *EmailWorkerPool) Stop() {
	log.Println("stopping email worker pool")
	p.cancel()
	close(p.taskQueue)
	p.wg.Wait()
	log.Println("email worker pool stopped")
}

// Enqueue adds a task to the queue (non-blocking, will log if pool is shutting down)
func (p *EmailWorkerPool) Enqueue(task EmailTask) {
	select {
	case p.taskQueue <- task:
		// Task enqueued successfully
	case <-p.ctx.Done():
		log.Println("worker pool is shutting down, discarding task")
	}
}

// Private helper methods

func (p *EmailWorkerPool) worker(id int) {
	defer p.wg.Done()

	log.Printf("email worker %d started", id)

	for {
		select {
		case task, ok := <-p.taskQueue:
			if !ok {
				log.Printf("email worker %d stopped", id)
				return
			}

			p.handleTask(id, task)

		case <-p.ctx.Done():
			log.Printf("email worker %d shutting down", id)
			return
		}
	}
}

func (p *EmailWorkerPool) handleTask(workerID int, task EmailTask) {
	err := p.emailProvider.SendEmail(p.ctx, task.Recipient, task.Subject, task.Body)
	if err != nil {
		log.Printf("email worker %d failed to send email to %s: %v", workerID, task.Recipient, err)
		return
	}

	log.Printf("email worker %d sent email to %s", workerID, task.Recipient)
}
