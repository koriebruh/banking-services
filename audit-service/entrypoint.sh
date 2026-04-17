#!/bin/sh
set -e

echo "Substituting environment variables in config..."
sed -i "s|\${DB_USERNAME}|${DB_USERNAME}|g" config.json
sed -i "s|\${DB_PASSWORD}|${DB_PASSWORD}|g" config.json
sed -i "s|\${DB_HOST}|${DB_HOST}|g" config.json
sed -i "s|\${DB_NAME}|${DB_NAME}|g" config.json

echo "Running database migrations..."
migrate -path db/migrations \
  -database "postgres://${DB_USERNAME}:${DB_PASSWORD}@audit-postgres:5432/${DB_NAME}?sslmode=disable" \
  up

echo "Starting audit-service..."
exec ./main