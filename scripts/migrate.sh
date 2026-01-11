#!/bin/bash

# Script to run database migrations
# Usage: ./scripts/migrate.sh [up|down]

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 [up|down]"
    echo "  up   - Apply all pending migrations"
    echo "  down - Rollback the last migration"
    exit 1
fi

COMMAND=$1
MIGRATIONS_DIR="migrations"

# Check if migrations directory exists
if [ ! -d "$MIGRATIONS_DIR" ]; then
    echo "Error: migrations directory not found at $MIGRATIONS_DIR"
    exit 1
fi

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Use DATABASE_URL from environment or default
DB_URL="${DATABASE_URL:-postgres://user:password@localhost:5432/auth_db}"

case "$COMMAND" in
    up)
        echo "Applying migrations..."
        for migration_file in "$MIGRATIONS_DIR"/*.up.sql; do
            if [ -f "$migration_file" ]; then
                echo "Running: $migration_file"
                psql "$DB_URL" -f "$migration_file"
            fi
        done
        echo "Migrations applied successfully!"
        ;;
    down)
        echo "Rolling back migrations..."
        # Apply down migrations in reverse order
        for migration_file in $(ls -r "$MIGRATIONS_DIR"/*.down.sql); do
            if [ -f "$migration_file" ]; then
                echo "Rolling back: $migration_file"
                psql "$DB_URL" -f "$migration_file"
            fi
        done
        echo "Migrations rolled back successfully!"
        ;;
    *)
        echo "Error: Unknown command '$COMMAND'"
        echo "Use 'up' or 'down'"
        exit 1
        ;;
esac
