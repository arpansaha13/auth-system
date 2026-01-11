# Authentication System

A production-grade, modular monolith authentication service built in **Golang** with **gRPC**, **PostgreSQL**, and **GORM**.

## Architecture

### Layered Pattern (MVC-inspired)

```
┌─────────────────────────────────────────────────────────────┐
│                    gRPC Controllers                          │
│              (Request Validation & Routing)                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                   Service Layer                              │
│         (Business Logic & Transactions)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Repository Layer                            │
│           (GORM & Database Abstractions)                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    PostgreSQL                                │
│                   Database                                   │
└─────────────────────────────────────────────────────────────┘
```

### Dependency Injection Flow

```
config.Config
    │
    ├── PasswordHasher → UserRepository
    │                └── AuthService ─┬─ SignupFlow
    │                   SessionRepository ─┤ LoginFlow
    │                   OTPRepository ─────┤ VerifyOTPFlow
    │                   Validator ────────┬─ RefreshFlow
    │                   EmailProvider
    │
    └── gRPC Server
        └── AuthServiceImpl (Controller)
            └── AuthService (injected)
```

### Database Schema (ERD)

```sql
users (Parent)
├── id (UUID, PK)
├── email (VARCHAR, UNIQUE, INDEX)
├── username (VARCHAR, UNIQUE, INDEX)
├── verified (BOOLEAN)
├── last_login (TIMESTAMP)
└── created_at (TIMESTAMP)
    │
    ├─── profiles (One-to-One, FK: user_id)
    │    ├── user_id (UUID, PK, FK)
    │    ├── first_name (VARCHAR)
    │    └── last_name (VARCHAR)
    │
    ├─── credentials (One-to-One, FK: user_id)
    │    ├── user_id (UUID, PK, FK)
    │    └── password_hash (VARCHAR)
    │
    ├─── otps (One-to-One, FK: user_id)
    │    ├── user_id (UUID, PK, FK)
    │    ├── hashed_code (VARCHAR)
    │    └── expires_at (TIMESTAMP)
    │
    └─── sessions (One-to-Many, FK: user_id, INDEX)
         ├── id (UUID, PK)
         ├── user_id (UUID, FK, INDEX)
         ├── token_hash (VARCHAR, UNIQUE)
         ├── expires_at (TIMESTAMP)
         └── created_at (TIMESTAMP)
```

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- PostgreSQL 16 (or use Docker)

### Development Setup

1. **Clone and setup environment:**

```bash
# Clone the repository
git clone <repo-url>
cd auth-system

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

2. **Start services with Docker:**

```bash
docker-compose up -d
```

3. **Apply migrations:**

```bash
# Run migrations using psql
psql postgres://user:password@localhost:5432/auth_db < migrations/0001_initial_schema.up.sql
```

4. **Start the server (if not using Docker):**

```bash
cd cmd/server
go run main.go -env development
```

### Testing

Run integration tests with Testcontainers:

```bash
go test -v -race ./tests/...
```

## Core Features

### 1. Signup/Verification Flow

**Signup:**
- Email validation and uniqueness check
- Password hashing (bcrypt)
- Atomic transaction: create user + credentials + profile
- Generate OTP (6-digit) with 10-minute expiry
- Send OTP via email (async background worker)

**OTP Verification:**
- Hash comparison (bcrypt)
- Expiry check
- Generate unique username: `{email_prefix}_{random_6_digits}` with collision retry (max 10)
- Atomic transaction: mark verified + set username + delete OTP
- Create session token automatically

**Constraints:**
- `users.email`: UNIQUE, NOT NULL, indexed
- `users.username`: UNIQUE, indexed
- Automatic cleanup of expired OTPs (background worker)

### 2. Login Flow

- Email + password authentication
- Verify email is confirmed
- Password hash verification (bcrypt)
- Create session token (32-byte random hex)
- Token hash stored in DB (SHA256)
- Return session token + expiry time

**Security:**
- Session tokens hashed with SHA256 + secret key
- TTL configurable (default: 30 minutes)
- Update last_login timestamp

### 3. Session Management

**Validate Session:**
- Extract token from gRPC metadata header
- Hash token with secret key
- Check existence and expiry in DB
- Return user_id and validity status

**Refresh Session:**
- Validate current token
- Generate new token
- Update token hash + extend TTL
- Return new token

**Automatic Cleanup:**
- Background worker runs every 5 minutes (configurable)
- Delete expired sessions
- Delete expired OTPs

### 4. Background Workers

**Email Worker Pool:**
- Configurable pool size (default: 5 workers)
- Async task queue (default: 100 tasks)
- SMTP support with fallback to mock provider for dev
- Sends verification emails with OTP

**Cleanup Worker:**
- Runs on configurable interval (default: 5 minutes)
- Removes expired sessions and OTPs
- Context-based timeout (30 seconds)

### 5. gRPC Interceptors

**Authorization Interceptor:**
- Extracts Bearer token from metadata
- Skips auth for public endpoints: Signup, Login, VerifyOTP
- Validates sessions for protected endpoints
- Adds token to context for handler access

**Recovery Interceptor:**
- Catches panics in handlers
- Returns gRPC Internal error status
- Logs panic details

**Logging Interceptor:**
- Logs method calls and errors
- Useful for debugging and monitoring

## Project Structure

```
auth-system/
├── cmd/
│   ├── server/
│   │   └── main.go              # Entry point with DI setup
│   └── migrate/
│       └── main.go              # Migration runner
├── internal/
│   ├── config/
│   │   └── config.go            # Configuration loader
│   ├── controller/
│   │   └── auth.go              # gRPC handler implementation
│   ├── domain/
│   │   ├── models.go            # GORM models
│   │   └── errors.go            # Custom error types
│   ├── middleware/
│   │   └── interceptor.go       # gRPC interceptors
│   ├── repository/
│   │   ├── user.go              # User DB operations
│   │   ├── otp.go               # OTP DB operations
│   │   └── session.go           # Session DB operations
│   ├── service/
│   │   └── auth.go              # Business logic
│   ├── utils/
│   │   ├── crypto.go            # Password/token hashing, OTP generation
│   │   ├── validator.go         # Input validation
│   │   └── db.go                # DB initialization
│   └── worker/
│       ├── email.go             # Email worker pool
│       ├── email_provider.go    # SMTP + Mock email
│       └── cleanup.go           # Cleanup cron job
├── pb/
│   ├── auth.pb.go               # Protobuf generated
│   └── auth_grpc.pb.go          # gRPC generated
├── proto/
│   └── auth.proto               # Service definition
├── migrations/
│   ├── 0001_initial_schema.up.sql
│   └── 0001_initial_schema.down.sql
├── scripts/
│   ├── protoc-gen.sh            # Protobuf code generation
│   └── migrate.sh               # Database migration runner
├── tests/
│   └── auth_test.go             # Integration tests
├── Dockerfile                   # Production image
├── Dockerfile.dev               # Development image with hot reload
├── docker-compose.yml           # Development setup
├── docker-compose.prod.yml      # Production setup
├── .env.example                 # Example configuration
├── .editorconfig                # Editor settings
├── .dockerignore                # Docker ignore rules
├── .gitignore                   # Git ignore rules
└── README.md                    # This file
```

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgres://user:password@localhost:5432/auth_db

# gRPC
GRPC_HOST=0.0.0.0
GRPC_PORT=50051

# Session
SESSION_TTL_MINUTES=30
SESSION_CLEANUP_INTERVAL_MINUTES=5

# Security
SECRET_KEY=your-secret-key-at-least-32-chars
JWT_SECRET=your-jwt-secret-at-least-32-chars

# Email
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=user
SMTP_PASSWORD=pass
EMAIL_FROM=noreply@example.com

# Environment
ENVIRONMENT=development|staging|production
LOG_LEVEL=debug|info|warn|error

# OTP
OTP_EXPIRY_MINUTES=10
OTP_LENGTH=6

# Worker Pool
EMAIL_WORKER_POOL_SIZE=5
EMAIL_TASK_QUEUE_SIZE=100
```

## Testing

### Run All Tests

```bash
go test -v -race -timeout 5m ./...
```

### Run Specific Tests

```bash
# Auth service tests
go test -v -race -timeout 5m ./tests -run TestSignupFlow

# Repository tests
go test -v -race ./internal/repository/...

# Service tests
go test -v -race ./internal/service/...
```

### Test Coverage

```bash
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Docker

### Development

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f auth-server

# Stop services
docker-compose down

# Clean up volumes
docker-compose down -v
```

### Production

```bash
# Build image
docker build -f Dockerfile -t auth-system:latest .

# Run with environment file
docker run --env-file .env.prod -p 50051:50051 auth-system:latest

# Or use docker-compose prod
docker-compose -f docker-compose.prod.yml up -d
```

## Security Considerations

### Password Hashing
- **Algorithm**: bcrypt with default cost (12 iterations)
- **Never stored**: Plain text passwords
- **Updated**: Only when user changes password

### Token Management
- **Generation**: 32-byte cryptographically secure random
- **Storage**: SHA256 hash with application secret
- **TTL**: Configurable (default 30 minutes)
- **Refresh**: Extends TTL, generates new token

### OTP Security
- **Format**: 6-digit numeric
- **Storage**: Bcrypt hashed
- **Expiry**: Configurable (default 10 minutes)
- **Cleanup**: Automatic via background worker

### Database Constraints
- **UNIQUE**: email, username, token_hash
- **Foreign Keys**: ON DELETE CASCADE
- **Indexes**: email, username, token_hash, user_id

## API Usage Examples

### Using grpcurl (CLI)

```bash
# Signup
grpcurl -plaintext \
  -d '{"email":"user@example.com","password":"securePass123"}' \
  localhost:50051 auth.AuthService/Signup

# Login
grpcurl -plaintext \
  -d '{"email":"user@example.com","password":"securePass123"}' \
  localhost:50051 auth.AuthService/Login

# Validate Session
grpcurl -plaintext \
  -H "authorization: Bearer <token>" \
  -d '{}' \
  localhost:50051 auth.AuthService/ValidateSession

# Refresh Session
grpcurl -plaintext \
  -H "authorization: Bearer <token>" \
  -d '{}' \
  localhost:50051 auth.AuthService/RefreshSession
```

### Using Go Client

```go
import (
    "context"
    "github.com/arpansaha13/auth-system/pb"
    "google.golang.org/grpc"
)

conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
client := pb.NewAuthServiceClient(conn)

resp, _ := client.Signup(context.Background(), &pb.SignupRequest{
    Email:    "user@example.com",
    Password: "securePass123",
})
```

## Database Migrations

### Manual Migrations

```bash
# Apply all up migrations
./scripts/migrate.sh up

# Rollback last migration
./scripts/migrate.sh down
```

### Using psql

```bash
# Apply schema
psql $DATABASE_URL < migrations/0001_initial_schema.up.sql

# Rollback
psql $DATABASE_URL < migrations/0001_initial_schema.down.sql
```

## 🔄 Protocol Buffers

### Regenerate from .proto

```bash
./scripts/protoc-gen.sh
```

### Service Definition

```protobuf
service AuthService {
  rpc Signup(SignupRequest) returns (SignupResponse);
  rpc VerifyOTP(VerifyOTPRequest) returns (VerifyOTPResponse);
  rpc Login(LoginRequest) returns (LoginResponse);
  rpc ValidateSession(ValidateSessionRequest) returns (ValidateSessionResponse);
  rpc RefreshSession(RefreshSessionRequest) returns (RefreshSessionResponse);
}
```

## Monitoring & Debugging

### Logs

```bash
# View all logs
docker-compose logs

# Follow logs in real-time
docker-compose logs -f auth-server

# Filter logs
docker-compose logs auth-server | grep ERROR
```

### Database

```bash
# Connect to database
psql postgres://user:password@localhost:5432/auth_db

# View tables
\dt

# Check indexes
\di

# View sessions
SELECT * FROM sessions WHERE expires_at > NOW();

# View expired OTPs for cleanup
SELECT * FROM otps WHERE expires_at < NOW();
```

## Deployment

### Prerequisites
- PostgreSQL 16+
- Go 1.23+ or Docker
- TLS certificates for production

### Production Checklist

- [ ] Set strong `SECRET_KEY` and `JWT_SECRET`
- [ ] Configure real SMTP service
- [ ] Use `ENVIRONMENT=production`
- [ ] Enable TLS for gRPC
- [ ] Set up monitoring/alerting
- [ ] Configure database backups
- [ ] Use environment-specific docker-compose.prod.yml
- [ ] Set up CI/CD pipeline
- [ ] Test failover and recovery

### Scaling

**Horizontal Scaling:**
- Run multiple instances behind load balancer
- Use PostgreSQL connection pooling (pgBouncer)
- Share SECRET_KEY across instances for token validation

**Vertical Scaling:**
- Increase EMAIL_WORKER_POOL_SIZE
- Increase DATABASE connection pool
- Tune SESSION_CLEANUP_INTERVAL

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
psql postgres://user:password@localhost:5432/auth_db

# Check logs
docker-compose logs postgres
```

### gRPC Server Won't Start

```bash
# Check port is available
lsof -i :50051

# Verify configuration
cat .env | grep GRPC
```

### Migration Failures

```bash
# Check migration file syntax
head -20 migrations/0001_initial_schema.up.sql

# Check for partial migrations
psql $DATABASE_URL -c "SELECT * FROM information_schema.tables"

# Rollback if needed
./scripts/migrate.sh down
```

## Support & Contribution

For issues, questions, or contributions:
1. Check existing documentation
2. Review test cases for examples
3. Submit issues with logs and reproduction steps
4. Follow code style and testing standards

---

Built with ❤️
