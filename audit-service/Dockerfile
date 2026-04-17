FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install migrate CLI for database migrations
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Ganti config-prod.json jadi config.json
RUN cp config-prod.json config.json

RUN go build -o main cmd/web/main.go

# -----------------------------------------------------------------------
FROM alpine:3.19

WORKDIR /app

RUN apk --no-cache add tzdata wget

COPY --from=builder /app/main .
COPY --from=builder /app/config.json .
COPY --from=builder /app/.env .
COPY --from=builder /app/secrets ./secrets
COPY --from=builder /app/db ./db
COPY --from=builder /go/bin/migrate /usr/local/bin/migrate

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8084

ENTRYPOINT ["./entrypoint.sh"]