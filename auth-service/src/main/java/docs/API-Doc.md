# Auth Service API Documentation

Base URL: `http://localhost:8080`

## Table of Contents
1. [Authentication Endpoints](#authentication-endpoints)
2. [User Management Endpoints](#user-management-endpoints)
3. [Error Responses](#error-responses)
4. [Response Format](#response-format)

---

## Authentication Endpoints

### 1.1 Register New Customer

Creates a new customer account in the system.

```
POST /api/v1/auth/register
Content-Type: application/json
```

**Request Body**
```json
{
  "full_name": "Budi Santoso",
  "email": "budi.santoso@example.com",
  "password": "SecurePass123!",
  "phone_number": "081234567890",
  "nik": "3271010101900001",
  "address": "Jl. Sudirman No. 10, Jakarta",
  "date_of_birth": "1990-05-15"
}
```

**Validation Rules**
- `full_name`: Required, 3-150 characters
- `email`: Required, valid email format, unique
- `password`: Required, min 8 characters, must contain uppercase, lowercase, number, and special character
- `phone_number`: Required, valid Indonesian phone format, unique
- `nik`: Required, exactly 16 digits, unique
- `address`: Optional, max 500 characters
- `date_of_birth`: Required, ISO 8601 date format (YYYY-MM-DD)

**Response `201 Created`** ✅
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_code": "CUST001",
    "full_name": "Budi Santoso",
    "email": "budi.santoso@example.com",
    "phone_number": "081234567890",
    "role": "CUSTOMER",
    "status": "PENDING_VERIFICATION",
    "email_verified": false,
    "created_at": "2026-02-24T10:00:00Z"
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440001",
    "service": "auth-service",
    "version": "v1"
  }
}
```

**Response `400 Bad Request`** ❌
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    {
      "nik": "NIK already registered",
      "password" :"Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    }
  ],
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440002",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

### 1.2 Login

Authenticates a user and returns access and refresh tokens.

```
POST /api/v1/auth/login
Content-Type: application/json
```

**Request Body**
```json
{
  "email": "budi.santoso@example.com",
  "password": "SecurePass123!"
}
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_expires_in": 604800,
    "user": {
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "role": "CUSTOMER"
    }
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440003",
    "service": "auth-service",
    "version": "v1"
  }
}
```

**Response `401 Unauthorized`** ❌
```json
{
  "success": false,
  "message": "Invalid email or password",
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440004",
    "service": "auth-service",
    "version": "v1"
  }
}
```

**Response `423 Locked`** ❌
```json
{
  "success": false,
  "message": "Account is locked due to multiple failed login attempts",
  "data": {
    "locked_until": "2026-02-24T11:00:00Z",
    "failed_attempts": 5
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440005",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

### 1.3 Refresh Access Token

Generates a new access token using a valid refresh token.

```
POST /api/v1/auth/refresh-token
Content-Type: application/json
```

**Request Body**
```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_expires_in": 604800
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440006",
    "service": "auth-service",
    "version": "v1"
  }
}
```

**Response `401 Unauthorized`** ❌
```json
{
  "success": false,
  "message": "Invalid or expired refresh token",
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440007",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

### 1.4 Logout

Revokes the current user's refresh token and invalidates the session.

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body**
```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "Logout successful",
  "data": {
    "logged_out_at": "2026-02-24T10:00:00Z"
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440008",
    "service": "auth-service",
    "version": "v1"
  }
}
```

**Response `401 Unauthorized`** ❌
```json
{
  "success": false,
  "message": "Unauthorized - Invalid or missing token",
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440009",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

### 1.5 Logout All Devices

Revokes all refresh tokens for the current user across all devices.

```
POST /api/v1/auth/logout-all
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "All sessions logged out successfully",
  "data": {
    "revoked_tokens_count": 3,
    "logged_out_at": "2026-02-24T10:00:00Z"
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440010",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

## User Management Endpoints

### 2.1 Get Current User Profile

Retrieves the authenticated user's profile information.

```
GET /api/v1/users/me
Authorization: Bearer <access_token>
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "User profile retrieved successfully",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_code": "CUST001",
    "full_name": "Budi Santoso",
    "email": "budi.santoso@example.com",
    "phone_number": "081234567890",
    "nik": "3271010101900001",
    "address": "Jl. Sudirman No. 10, Jakarta",
    "date_of_birth": "1990-05-15",
    "role": "CUSTOMER",
    "status": "ACTIVE",
    "email_verified": true,
    "last_login_at": "2026-02-24T09:00:00Z",
    "created_at": "2026-02-24T08:00:00Z",
    "updated_at": "2026-02-24T09:00:00Z"
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440011",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

### 2.2 Update User Profile

Updates the authenticated user's profile information.

```
PUT /api/v1/users/me
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body**
```json
{
  "full_name": "Budi Santoso Updated",
  "phone_number": "081234567899",
  "address": "Jl. Sudirman No. 20, Jakarta"
}
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_code": "CUST001",
    "full_name": "Budi Santoso Updated",
    "email": "budi.santoso@example.com",
    "phone_number": "081234567899",
    "address": "Jl. Sudirman No. 20, Jakarta",
    "updated_at": "2026-02-24T10:00:00Z"
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440012",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

### 2.3 Change Password

Changes the authenticated user's password.

```
PUT /api/v1/users/me/password
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body**
```json
{
  "current_password": "SecurePass123!",
  "new_password": "NewSecurePass456!",
  "confirm_password": "NewSecurePass456!"
}
```

**Response `200 OK`** ✅
```json
{
  "success": true,
  "message": "Password changed successfully",
  "data": {
    "changed_at": "2026-02-24T10:00:00Z"
  },
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440013",
    "service": "auth-service",
    "version": "v1"
  }
}
```

**Response `400 Bad Request`** ❌
```json
{
  "success": false,
  "message": "Invalid current password",
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440014",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

## Error Responses

### Standard Error Response Format

All error responses follow this format:

```json
{
  "success": false,
  "message": "Human-readable error message",
  "errors": [
    {
      "field_name": "message"
    }
  ],
  "meta": {
    "timestamp": "2026-02-24T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440015",
    "service": "auth-service",
    "version": "v1"
  }
}
```



### Success Response

```json
{
  "success": true,
  "message": "Operation description",
  "data": {
    // Response data object
  },
  "meta": {
    "timestamp": "ISO 8601 timestamp",
    "correlation_id": "UUID for request tracking",
    "service": "auth-service",
    "version": "v1"
  }
}
```

### Error Response

```json
{
  "success": false,
  "message": "Error description",
  "errors": [
    {
      "field_name": "message"
    }
  ],
  "meta": {
    "timestamp": "ISO 8601 timestamp",
    "correlation_id": "UUID for request tracking",
    "service": "auth-service",
    "version": "v1"
  }
}
```

---

## Headers

### Common Request Headers

```
Content-Type: application/json
Accept: application/json
X-Correlation-Id: <optional-correlation-id>
Authorization: Bearer <access_token> (for protected endpoints)
```

### Common Response Headers

```
Content-Type: application/json
X-Correlation-Id: <correlation-id>
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1614249600
```

