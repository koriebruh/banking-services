# 🏦 Auth Service — Banking Authentication Microservice

Production-grade authentication microservice for a banking platform built with **Spring Boot 4.x + WebFlux (reactive)**.

---

## ✨ Features

- 📧 Email OTP verification on registration
- 🔐 Multi-Factor Authentication (TOTP / Google Authenticator)
- 🎫 JWT authentication — access token + refresh token
- 🔑 Password management (change, forgot, reset)
- 🛡️ Redis sliding window rate limiting per IP per endpoint
- 📨 Kafka event publishing for audit trail
- 🔒 Account lockout after 5 consecutive failed login attempts

---

## 🛠️ Tech Stack

| Layer | Technology                                 |
|---|--------------------------------------------|
| Runtime | Java 25, Spring Boot 4.0.3                 |
| Web | Spring WebFlux (reactive, non-blocking)    |
| Database | PostgreSQL + R2DBC + Flyway                |
| Cache / Rate Limit | Redis (Lettuce reactive)                   |
| Messaging | Apache Kafka (KRaft mode)                  |
| Security | Spring Security + JWT (JJWT 0.12.x) + TOTP |
| Mail | JavaMail + Mailhog (dev)                   |
| Docs | SpringDoc OpenAPI 3.x (Swagger UI)         |
| Monitoring | Actuator + Prometheus + Grafana            |

---

## 🚀 Running the Application

### 🐳 Docker (Recommended)

> ⚠️ **Start shared infrastructure first** — Kafka, Prometheus, Grafana, and Jaeger live in a separate compose file outside this directory.

```bash
# 1. Start shared infrastructure first
docker compose -f ../docker-compose.shared.yml up -d

# 2. Setup environment
cp .env.example .env
# Edit .env — fill in DB_PASSWORD, REDIS_PASSWORD, JWT_SECRET

# 3. Start auth-service
docker compose up -d
```

> This service joins both `auth-network` (internal) and `shared-network` (to reach Kafka).

---

### 💻 Local (Without Docker)

> ⚠️ **Prerequisites:** Make sure these services are installed and running locally.

| Service | Default Port |
|---|---|
| PostgreSQL | `5432` |
| Redis | `6379` |
| Kafka | `9092` |
| Mailhog SMTP | `1025` |
| Mailhog Web UI | `8025` |

**Steps:**

```bash
# 1. Setup environment
cp .env.example .env
```

```yaml
# 2. Update src/main/resources/application.yaml to point to localhost
spring:
  r2dbc:
    url: r2dbc:postgresql://localhost:5432/auth_db
  data:
    redis:
      host: localhost
  kafka:
    bootstrap-servers: localhost:9092
  mail:
    host: localhost
```

```bash
# 3. Run
./mvnw spring-boot:run        # Linux/Mac
.\mvnw spring-boot:run        # Windows
```

Service runs at `http://localhost:8081` 🎉

---

## 🧪 Running Tests

```bash
./mvnw test           # Linux/Mac
.\mvnw test           # Windows
```

---

## 📡 API Endpoints

Base URL: `http://localhost:8081/api/v1/auth`

### 🔓 Public (no token required)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/register` | Register new user |
| `POST` | `/login` | Login with email + password |
| `POST` | `/verify-email` | Verify email with OTP |
| `POST` | `/resend-verification` | Resend email verification OTP |
| `POST` | `/forgot-password` | Request password reset OTP |
| `POST` | `/reset-password` | Reset password using OTP |

### 🔐 Protected (require `Authorization: Bearer <token>`)

| Method | Endpoint | Token Type | Description |
|---|---|---|---|
| `POST` | `/mfa/setup` | Access Token | Generate QR code for Google Authenticator |
| `POST` | `/mfa/setup/verify` | Access Token | Activate MFA with first OTP |
| `POST` | `/mfa/validate` | MFA Token | Exchange MFA token + OTP → full token pair |
| `POST` | `/refresh` | Refresh Token | Get new access token |
| `POST` | `/logout` | Access Token | Revoke current session |
| `POST` | `/change-password` | Access Token | Change password |

### 🔄 Authentication Flow

```
# Without MFA
POST /login → { access_token, refresh_token }

# With MFA
POST /login            → { mfa_token }
POST /mfa/validate     → { access_token, refresh_token }

# Refresh
POST /refresh (refresh_token in Authorization header) → { access_token }
```

---

## 🔑 Environment Variables

| Variable | Description |
|---|---|
| `DB_PASSWORD` | PostgreSQL password |
| `REDIS_PASSWORD` | Redis password |
| `JWT_SECRET` | JWT signing secret (min 64 hex chars / 256-bit) |

> ⚠️ **Never commit `.env` to version control!** Make sure `.env` is in `.gitignore`.

---

## 📁 Project Structure

```
src/main/java/com/koriebruh/authservice/
├── 🔧 config/        # Security, Kafka, OpenAPI, RateLimit config
├── 🎮 controller/    # AuthController
├── 📦 dto/           # Request/Response DTOs, ApiResponse wrapper
├── 🗃️  entity/        # R2DBC entities (User, RefreshToken)
├── 📨 event/         # Kafka publisher, AuthEvent, AuthEventType
├── ⚠️  exception/     # GlobalExceptions, UserExceptions
├── 🔍 filter/        # JwtAuthenticationFilter, RateLimitFilter
├── 🗄️  repository/    # UserRepository, RefreshTokenRepository
├── ⚙️  service/       # AuthService, EmailService, OtpService, RateLimiterService
└── 🛠️  util/          # JwtUtil
```