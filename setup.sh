#!/bin/bash

# Quick Setup Script for Auth System
# This script sets up the development environment

set -e

echo "🚀 Auth System - Quick Setup"
echo "================================"

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed"
    exit 1
fi

if ! command -v go &> /dev/null; then
    echo "⚠️  Go is not installed (required for running locally without Docker)"
fi

echo "✅ Prerequisites met"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    echo "✅ .env file created (please update with your values)"
fi

# Start Docker services
echo "🐳 Starting Docker services..."
docker-compose up -d

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker-compose exec -T postgres pg_isready -U user > /dev/null 2>&1; then
        echo "✅ Database is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "❌ Database failed to start"
    exit 1
fi

# Run migrations
echo "🗄️  Running migrations..."
DATABASE_URL="postgres://user:password@localhost:5432/auth_db" go run cmd/migrate/main.go up

if [ $? -eq 0 ]; then
    echo "✅ Migrations completed"
else
    echo "⚠️  Migrations may have failed, but continuing..."
fi

# Display next steps
echo ""
echo "✅ Setup complete!"
echo ""
echo "📝 Next steps:"
echo "1. Review .env file: nano .env"
echo "2. Run tests: make test"
echo "3. View logs: docker-compose logs -f auth-server"
echo "4. Test API:"
echo "   grpcurl -plaintext \\"
echo "     -d '{\"email\":\"test@example.com\",\"password\":\"Test123456\"}' \\"
echo "     localhost:50051 auth.AuthService/Signup"
echo ""
echo "📖 Documentation:"
echo "- README.md - Project overview"
echo "- ARCHITECTURE.md - Architecture decisions"
echo "- PROJECT_INDEX.md - File structure and flows"
echo "- DEPLOYMENT.md - Deployment guide"
echo ""
echo "🛑 To stop services: docker-compose down"
echo "🗑️  To clean up volumes: docker-compose down -v"
