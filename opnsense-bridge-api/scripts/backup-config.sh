#!/bin/bash

# backup-config.sh - Backup configuration and logs
# Uses BACKUP_DIRECTORY and BACKUP_RETENTION_DAYS from .env

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Set backup directory
BACKUP_DIR="${BACKUP_DIRECTORY:-/app/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/config_$TIMESTAMP.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup .env, certs, and logs
tar -czf "$BACKUP_FILE" .env certs logs
if [ $? -eq 0 ]; then
    echo "Backup created: $BACKUP_FILE"
else
    echo "Error: Failed to create backup"
    exit 1
fi

# Clean old backups
find "$BACKUP_DIR" -name "config_*.tar.gz" -mtime +${BACKUP_RETENTION_DAYS:-30} -delete
echo "Cleaned backups older than $BACKUP_RETENTION_DAYS days"