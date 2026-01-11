.PHONY: help build dev test test-coverage docker-build docker-up docker-down migrate-up migrate-down clean

# Variables
BINARY_NAME=auth-server
GO=go
DOCKER=docker
DOCKER_COMPOSE=docker-compose

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the application
	@echo "Building $(BINARY_NAME)..."
	@$(GO) build -o bin/$(BINARY_NAME) ./cmd/server
	@echo "Build complete: bin/$(BINARY_NAME)"

dev: ## Run in development mode with hot reload
	@echo "Starting development server..."
	@$(DOCKER_COMPOSE) up -d
	@echo "Services started. Check docker-compose logs for details"

dev-down: ## Stop development services
	@echo "Stopping development services..."
	@$(DOCKER_COMPOSE) down

dev-logs: ## View development logs
	@$(DOCKER_COMPOSE) logs -f auth-server

dev-logs-db: ## View database logs
	@$(DOCKER_COMPOSE) logs -f postgres

test: ## Run integration tests
	@echo "Running tests..."
	@$(GO) test -v -race -timeout 5m ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@$(GO) test -v -race -coverprofile=coverage.out -timeout 5m ./...
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-one: ## Run single test (use TEST=TestName)
	@$(GO) test -v -race -run $(TEST) -timeout 5m ./...

protoc: ## Generate protobuf code
	@echo "Generating protobuf code..."
	@bash scripts/protoc-gen.sh

migrate-up: ## Run migrations
	@echo "Running migrations..."
	@bash scripts/migrate.sh up

migrate-down: ## Rollback migrations
	@echo "Rolling back migrations..."
	@bash scripts/migrate.sh down

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@$(DOCKER) build -f Dockerfile -t auth-system:latest .
	@echo "Image built: auth-system:latest"

docker-build-dev: ## Build development Docker image
	@echo "Building development Docker image..."
	@$(DOCKER) build -f Dockerfile.dev -t auth-system:dev .
	@echo "Image built: auth-system:dev"

docker-up: ## Start services with Docker
	@echo "Starting Docker services..."
	@$(DOCKER_COMPOSE) up -d
	@echo "Services started"

docker-down: ## Stop Docker services
	@echo "Stopping Docker services..."
	@$(DOCKER_COMPOSE) down

docker-clean: ## Remove Docker services and volumes
	@echo "Cleaning Docker resources..."
	@$(DOCKER_COMPOSE) down -v
	@echo "Cleaned"

lint: ## Run linter
	@echo "Running linter..."
	@$(GO) run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run ./...

fmt: ## Format code
	@echo "Formatting code..."
	@$(GO) fmt ./...
	@echo "Code formatted"

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@$(GO) clean -testcache
	@echo "Cleaned"

tidy: ## Tidy dependencies
	@echo "Tidying dependencies..."
	@$(GO) mod tidy
	@echo "Dependencies tidied"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@$(GO) mod download
	@echo "Dependencies downloaded"

run: build ## Build and run the application
	@echo "Running $(BINARY_NAME)..."
	@./bin/$(BINARY_NAME) -env development

all: clean deps build test ## Run everything

.DEFAULT_GOAL := help
