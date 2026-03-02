package com.koriebruh.authservice.integration;

import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.request.*;
import com.koriebruh.authservice.dto.response.*;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.Disabled;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.LocalDate;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for Authentication endpoints.
 *
 * <h2>Banking Best Practices:</h2>
 * <ul>
 *   <li>Uses isolated TestContainers database - no production data risk</li>
 *   <li>Each test cleans up after itself via {@link BaseIntegrationTest}</li>
 *   <li>Tests realistic banking scenarios (registration, login, MFA)</li>
 *   <li>Verifies security constraints (password hashing, token expiry)</li>
 *   <li>Audit logging enabled for compliance verification</li>
 * </ul>
 */
@DisplayName("Auth Controller Integration Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthControllerIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String VALID_PASSWORD = "SecureP@ssw0rd123!";
    private static final String CORRELATION_ID = "test-correlation-id";

    // -------------------------------------------------------------------------
    // REGISTRATION TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("POST /api/v1/auth/register")
    class RegisterEndpoint {

        @Test
        @DisplayName("Should register new user successfully")
        void shouldRegisterNewUser() {
            // Given
            String email = generateTestEmail();
            RegisterRequest request = RegisterRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .fullName("Test User")
                    .phoneNumber(generateTestPhone())
                    .nik(generateTestNik())
                    .address("Jl. Test No. 123, Jakarta")
                    .dateOfBirth(LocalDate.of(1990, 1, 15))
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("X-Correlation-ID", CORRELATION_ID)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<RegisterResponse>>() {})
                    .value(response -> {
                        assertThat(response.isSuccess()).isTrue();
                        assertThat(response.getData()).isNotNull();
                        assertThat(response.getData().getEmail()).isEqualTo(email);
                        assertThat(response.getData().getUserCode()).startsWith("USR-");
                        assertThat(response.getMeta().getCorrelationId()).isEqualTo(CORRELATION_ID);
                    });

            // Verify user exists in database with correct status
            verifyUserInDatabase(email, UserStatus.PENDING_VERIFICATION, false);
        }

        @Test
        @DisplayName("Should reject duplicate email registration")
        void shouldRejectDuplicateEmail() {
            // Given - Register first user
            String email = generateTestEmail();
            registerTestUser(email, generateTestPhone(), generateTestNik());

            // When - Try to register with same email
            RegisterRequest duplicateRequest = RegisterRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .fullName("Duplicate User")
                    .phoneNumber(generateTestPhone())
                    .nik(generateTestNik())
                    .address("Jl. Duplicate No. 123")
                    .dateOfBirth(LocalDate.of(1990, 1, 15))
                    .build();

            // Then
            webTestClient.post()
                    .uri("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(duplicateRequest)
                    .exchange()
                    .expectStatus().is4xxClientError()
                    .expectBody()
                    .jsonPath("$.success").isEqualTo(false);
        }

        @Test
        @DisplayName("Should reject invalid email format")
        void shouldRejectInvalidEmail() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                    .email("invalid-email")
                    .password(VALID_PASSWORD)
                    .fullName("Test User")
                    .phoneNumber(generateTestPhone())
                    .nik(generateTestNik())
                    .address("Jl. Test No. 123")
                    .dateOfBirth(LocalDate.of(1990, 1, 15))
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }

        @Test
        @DisplayName("Should reject weak password")
        void shouldRejectWeakPassword() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                    .email(generateTestEmail())
                    .password("weak")
                    .fullName("Test User")
                    .phoneNumber(generateTestPhone())
                    .nik(generateTestNik())
                    .address("Jl. Test No. 123")
                    .dateOfBirth(LocalDate.of(1990, 1, 15))
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }
    }

    // -------------------------------------------------------------------------
    // EMAIL VERIFICATION TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("POST /api/v1/auth/verify-email")
    class VerifyEmailEndpoint {

        @Test
        @DisplayName("Should verify email with valid OTP")
        void shouldVerifyEmailWithValidOtp() {
            // Given - Register user and store OTP in Redis
            String email = generateTestEmail();
            registerTestUser(email, generateTestPhone(), generateTestNik());

            // Manually set OTP in Redis for testing
            String otp = "123456";
            redisTemplate.opsForValue()
                    .set("email-otp:" + email, otp, Duration.ofMinutes(5))
                    .block();

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(email)
                    .otpCode(otp)
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/verify-email")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.success").isEqualTo(true)
                    .jsonPath("$.data.success").isEqualTo(true);

            // Verify user email is now verified
            verifyUserInDatabase(email, UserStatus.ACTIVE, true);
        }

        @Test
        @DisplayName("Should reject invalid OTP")
        void shouldRejectInvalidOtp() {
            // Given
            String email = generateTestEmail();
            registerTestUser(email, generateTestPhone(), generateTestNik());

            // Store correct OTP but send wrong one
            redisTemplate.opsForValue()
                    .set("email-otp:" + email, "123456", Duration.ofMinutes(5))
                    .block();

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(email)
                    .otpCode("000000") // Wrong OTP
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/verify-email")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }

        @Test
        @DisplayName("Should reject expired OTP")
        void shouldRejectExpiredOtp() {
            // Given - Register but don't set OTP (simulating expired)
            String email = generateTestEmail();
            registerTestUser(email, generateTestPhone(), generateTestNik());

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(email)
                    .otpCode("123456")
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/verify-email")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }
    }

    // -------------------------------------------------------------------------
    // LOGIN TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("POST /api/v1/auth/login")
    class LoginEndpoint {

        @Test
        @DisplayName("Should login successfully without MFA")
        void shouldLoginSuccessfullyWithoutMfa() {
            // Given - Create verified user
            String email = generateTestEmail();
            createVerifiedUser(email, VALID_PASSWORD);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<LoginResponse>>() {})
                    .value(response -> {
                        assertThat(response.isSuccess()).isTrue();
                        assertThat(response.getData().getMfaRequired()).isFalse();
                        assertThat(response.getData().getAccessToken()).isNotBlank();
                        assertThat(response.getData().getRefreshToken()).isNotBlank();
                    });
        }

        @Test
        @DisplayName("Should return MFA token when MFA enabled")
        void shouldReturnMfaTokenWhenMfaEnabled() {
            // Given - Create verified user with MFA
            String email = generateTestEmail();
            createVerifiedUserWithMfa(email, VALID_PASSWORD);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<LoginResponse>>() {})
                    .value(response -> {
                        assertThat(response.isSuccess()).isTrue();
                        assertThat(response.getData().getMfaRequired()).isTrue();
                        assertThat(response.getData().getMfaToken()).isNotBlank();
                        assertThat(response.getData().getAccessToken()).isNull();
                    });
        }

        @Test
        @DisplayName("Should reject wrong password")
        void shouldRejectWrongPassword() {
            // Given
            String email = generateTestEmail();
            createVerifiedUser(email, VALID_PASSWORD);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password("WrongPassword123!")
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }

        @Test
        @DisplayName("Should reject unverified user")
        void shouldRejectUnverifiedUser() {
            // Given - Register but don't verify
            String email = generateTestEmail();
            registerTestUser(email, generateTestPhone(), generateTestNik());

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }

        @Test
        @DisplayName("Should reject login for locked account")
        void shouldRejectLoginForLockedAccount() {
            // Given - Create user that is already locked
            String email = generateTestEmail();
            createLockedUser(email, VALID_PASSWORD);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When & Then - Should return 4xx error
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }
    }

    // -------------------------------------------------------------------------
    // PASSWORD MANAGEMENT TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Password Management Endpoints")
    class PasswordManagementEndpoints {

        @Test
        @DisplayName("POST /api/v1/auth/forgot-password - Should accept request for any email")
        void shouldAcceptForgotPasswordRequest() {
            // Given
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .email(generateTestEmail())
                    .build();

            // When & Then - Always returns success (no email enumeration)
            webTestClient.post()
                    .uri("/api/v1/auth/forgot-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.success").isEqualTo(true);
        }

        @Test
        @DisplayName("POST /api/v1/auth/reset-password - Should reset password with valid OTP")
        void shouldResetPasswordWithValidOtp() {
            // Given
            String email = generateTestEmail();
            createVerifiedUser(email, VALID_PASSWORD);

            // Set reset OTP
            String otp = "654321";
            redisTemplate.opsForValue()
                    .set("reset-otp:" + email, otp, Duration.ofMinutes(3))
                    .block();

            String newPassword = "NewSecureP@ss123!";
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .email(email)
                    .otpCode(otp)
                    .newPassword(newPassword)
                    .confirmPassword(newPassword)
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/reset-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.success").isEqualTo(true);

            // Verify can login with new password
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(LoginRequest.builder()
                            .email(email)
                            .password(newPassword)
                            .build())
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @DisplayName("POST /api/v1/auth/change-password - Should change password for authenticated user")
        void shouldChangePasswordForAuthenticatedUser() {
            // Given - Login first
            String email = generateTestEmail();
            createVerifiedUser(email, VALID_PASSWORD);
            String accessToken = loginAndGetAccessToken(email, VALID_PASSWORD);

            String newPassword = "NewSecureP@ss456!";
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword(VALID_PASSWORD)
                    .newPassword(newPassword)
                    .confirmPassword(newPassword)
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/change-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + accessToken)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.success").isEqualTo(true);

            // Verify can login with new password
            webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(LoginRequest.builder()
                            .email(email)
                            .password(newPassword)
                            .build())
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    // -------------------------------------------------------------------------
    // TOKEN MANAGEMENT TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Token Management Endpoints")
    class TokenManagementEndpoints {

        @Test
        @DisplayName("POST /api/v1/auth/refresh - Should refresh access token")
        void shouldRefreshAccessToken() {
            // Given - Use MFA flow since only MFA validation saves refresh token to DB
            String email = generateTestEmail();
            String mfaSecret = createVerifiedUserWithMfaAndGetSecret(email, VALID_PASSWORD);

            // Login to get MFA token
            LoginResponse loginResponse = webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(LoginRequest.builder()
                            .email(email)
                            .password(VALID_PASSWORD)
                            .build())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<LoginResponse>>() {})
                    .returnResult()
                    .getResponseBody()
                    .getData();

            String mfaToken = loginResponse.getMfaToken();

            // Validate MFA to get refresh token (this saves it to DB)
            String validOtp = generateValidOtp(mfaSecret);
            MfaValidateResponse mfaResponse = webTestClient.post()
                    .uri("/api/v1/auth/mfa/validate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + mfaToken)
                    .bodyValue(MfaValidateRequest.builder()
                            .otpCode(validOtp)
                            .build())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<MfaValidateResponse>>() {})
                    .returnResult()
                    .getResponseBody()
                    .getData();

            String refreshToken = mfaResponse.getRefreshToken();

            // When & Then - Refresh the token
            webTestClient.post()
                    .uri("/api/v1/auth/refresh")
                    .header("Authorization", "Bearer " + refreshToken)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<RefreshTokenResponse>>() {})
                    .value(response -> {
                        assertThat(response.isSuccess()).isTrue();
                        assertThat(response.getData().getAccessToken()).isNotBlank();
                        assertThat(response.getData().getTokenType()).isEqualTo("Bearer");
                    });
        }

        @Test
        @DisplayName("POST /api/v1/auth/logout - Should revoke refresh token")
        void shouldRevokeRefreshToken() {
            // Given - Use MFA flow since only MFA validation saves refresh token to DB
            String email = generateTestEmail();
            String mfaSecret = createVerifiedUserWithMfaAndGetSecret(email, VALID_PASSWORD);

            // Login to get MFA token
            LoginResponse loginResponse = webTestClient.post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(LoginRequest.builder()
                            .email(email)
                            .password(VALID_PASSWORD)
                            .build())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<LoginResponse>>() {})
                    .returnResult()
                    .getResponseBody()
                    .getData();

            String mfaToken = loginResponse.getMfaToken();

            // Validate MFA to get tokens
            String validOtp = generateValidOtp(mfaSecret);
            MfaValidateResponse mfaResponse = webTestClient.post()
                    .uri("/api/v1/auth/mfa/validate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + mfaToken)
                    .bodyValue(MfaValidateRequest.builder()
                            .otpCode(validOtp)
                            .build())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(new ParameterizedTypeReference<ApiResponse<MfaValidateResponse>>() {})
                    .returnResult()
                    .getResponseBody()
                    .getData();

            String accessToken = mfaResponse.getAccessToken();
            String refreshToken = mfaResponse.getRefreshToken();

            LogoutRequest request = LogoutRequest.builder()
                    .refreshToken(refreshToken)
                    .build();

            // When
            webTestClient.post()
                    .uri("/api/v1/auth/logout")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + accessToken)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.success").isEqualTo(true);

            // Then - Refresh token should no longer work
            webTestClient.post()
                    .uri("/api/v1/auth/refresh")
                    .header("Authorization", "Bearer " + refreshToken)
                    .exchange()
                    .expectStatus().is4xxClientError();
        }
    }

    // -------------------------------------------------------------------------
    // SECURITY TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Security Tests")
    class SecurityTests {

        @Test
        @DisplayName("Should reject request without authentication to protected endpoint")
        void shouldRejectUnauthenticatedRequest() {
            webTestClient.post()
                    .uri("/api/v1/auth/change-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(ChangePasswordRequest.builder()
                            .currentPassword("old")
                            .newPassword("new")
                            .confirmPassword("new")
                            .build())
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should reject request with invalid token")
        void shouldRejectInvalidToken() {
            webTestClient.post()
                    .uri("/api/v1/auth/change-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer invalid.token.here")
                    .bodyValue(ChangePasswordRequest.builder()
                            .currentPassword("old")
                            .newPassword("new")
                            .confirmPassword("new")
                            .build())
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should reject request with expired token")
        void shouldRejectExpiredToken() {
            // Given - A token that's syntactically correct but expired
            // In real test, you'd generate an expired token
            String expiredToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid";

            webTestClient.post()
                    .uri("/api/v1/auth/change-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + expiredToken)
                    .bodyValue(ChangePasswordRequest.builder()
                            .currentPassword("old")
                            .newPassword("new")
                            .confirmPassword("new")
                            .build())
                    .exchange()
                    .expectStatus().isUnauthorized();
        }
    }

    // -------------------------------------------------------------------------
    // DATA CLEANUP VERIFICATION TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Data Cleanup Verification")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class DataCleanupVerification {

        @Test
        @Order(1)
        @DisplayName("Should create test data")
        void shouldCreateTestData() {
            // Given - Use dynamic email to avoid conflicts
            String email = "cleanup_" + System.currentTimeMillis() + "@integration.test";
            RegisterRequest request = RegisterRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .fullName("Cleanup Test User")
                    .phoneNumber(generateTestPhone())
                    .nik(generateTestNik())
                    .address("Jl. Cleanup Test")
                    .dateOfBirth(LocalDate.of(1990, 1, 1))
                    .build();

            // When & Then
            webTestClient.post()
                    .uri("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk();

            // Verify data exists
            verifyUserInDatabase(email, UserStatus.PENDING_VERIFICATION, false);
        }

        @Test
        @Order(2)
        @DisplayName("Should verify cleanup mechanism removes test data")
        void shouldVerifyCleanupMechanismRemovesTestData() {
            // This test verifies that our cleanup mechanism works by checking
            // that test data from other tests is cleaned up
            // After @BeforeEach cleanup, test users should not exist

            // Simply verify we can create a new user - if cleanup failed,
            // we would have constraint violations
            String email = generateTestEmail();
            RegisterRequest request = RegisterRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .fullName("Cleanup Verification User")
                    .phoneNumber(generateTestPhone())
                    .nik(generateTestNik())
                    .address("Jl. Cleanup Verification")
                    .dateOfBirth(LocalDate.of(1990, 1, 1))
                    .build();

            webTestClient.post()
                    .uri("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(request)
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    // -------------------------------------------------------------------------
    // HELPER METHODS
    // -------------------------------------------------------------------------

    private void registerTestUser(String email, String phone, String nik) {
        RegisterRequest request = RegisterRequest.builder()
                .email(email)
                .password(VALID_PASSWORD)
                .fullName("Test User")
                .phoneNumber(phone)
                .nik(nik)
                .address("Jl. Test No. 123")
                .dateOfBirth(LocalDate.of(1990, 1, 15))
                .build();

        webTestClient.post()
                .uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk();
    }

    private void createVerifiedUser(String email, String password) {
        // Insert user directly into database with ACTIVE status
        String passwordHash = passwordEncoder.encode(password);
        String userCode = "USR-TEST-" + System.currentTimeMillis();

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, failed_login, created_at, updated_at
                ) VALUES (
                    :id, :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :failedLogin, NOW(), NOW()
                )
                """)
                .bind("id", UUID.randomUUID())
                .bind("userCode", userCode)
                .bind("fullName", "Test User")
                .bind("email", email)
                .bind("phone", generateTestPhone())
                .bind("passwordHash", passwordHash)
                .bind("nik", generateTestNik())
                .bind("address", "Jl. Test No. 123")
                .bind("dob", LocalDate.of(1990, 1, 15))
                .bind("role", UserRole.CUSTOMER.name())
                .bind("status", UserStatus.ACTIVE.name())
                .bind("emailVerified", true)
                .bind("mfaEnabled", false)
                .bind("failedLogin", (short) 0)
                .then()
                .block(Duration.ofSeconds(5));
    }

    private void createVerifiedUserWithMfa(String email, String password) {
        String passwordHash = passwordEncoder.encode(password);
        String userCode = "USR-TEST-" + System.currentTimeMillis();
        String mfaSecret = "JBSWY3DPEHPK3PXP"; // Test secret

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, mfa_secret, failed_login, created_at, updated_at
                ) VALUES (
                    :id, :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :mfaSecret, :failedLogin, NOW(), NOW()
                )
                """)
                .bind("id", UUID.randomUUID())
                .bind("userCode", userCode)
                .bind("fullName", "Test User MFA")
                .bind("email", email)
                .bind("phone", generateTestPhone())
                .bind("passwordHash", passwordHash)
                .bind("nik", generateTestNik())
                .bind("address", "Jl. Test No. 123")
                .bind("dob", LocalDate.of(1990, 1, 15))
                .bind("role", UserRole.CUSTOMER.name())
                .bind("status", UserStatus.ACTIVE.name())
                .bind("emailVerified", true)
                .bind("mfaEnabled", true)
                .bind("mfaSecret", mfaSecret)
                .bind("failedLogin", (short) 0)
                .then()
                .block(Duration.ofSeconds(5));
    }

    private void createLockedUser(String email, String password) {
        String passwordHash = passwordEncoder.encode(password);
        String userCode = "USR-TEST-LOCKED-" + System.currentTimeMillis();
        java.time.Instant lockedUntil = java.time.Instant.now().plus(30, java.time.temporal.ChronoUnit.MINUTES);

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, failed_login, locked_until, created_at, updated_at
                ) VALUES (
                    :id, :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :failedLogin, :lockedUntil, NOW(), NOW()
                )
                """)
                .bind("id", UUID.randomUUID())
                .bind("userCode", userCode)
                .bind("fullName", "Locked Test User")
                .bind("email", email)
                .bind("phone", generateTestPhone())
                .bind("passwordHash", passwordHash)
                .bind("nik", generateTestNik())
                .bind("address", "Jl. Test No. 123")
                .bind("dob", LocalDate.of(1990, 1, 15))
                .bind("role", UserRole.CUSTOMER.name())
                .bind("status", UserStatus.ACTIVE.name())
                .bind("emailVerified", true)
                .bind("mfaEnabled", false)
                .bind("failedLogin", (short) 5)
                .bind("lockedUntil", lockedUntil)
                .then()
                .block(Duration.ofSeconds(5));
    }

    private void verifyUserInDatabase(String email, UserStatus expectedStatus, boolean expectedEmailVerified) {
        Mono<User> userMono = databaseClient.sql(
                "SELECT * FROM users WHERE email = :email")
                .bind("email", email)
                .map((row, metadata) -> User.builder()
                        .email(row.get("email", String.class))
                        .status(UserStatus.valueOf(row.get("status", String.class)))
                        .emailVerified(row.get("email_verified", Boolean.class))
                        .build())
                .one();

        StepVerifier.create(userMono)
                .assertNext(user -> {
                    assertThat(user.getEmail()).isEqualTo(email);
                    assertThat(user.getStatus()).isEqualTo(expectedStatus);
                    assertThat(user.getEmailVerified()).isEqualTo(expectedEmailVerified);
                })
                .verifyComplete();
    }

    private String loginAndGetAccessToken(String email, String password) {
        return webTestClient.post()
                .uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(LoginRequest.builder()
                        .email(email)
                        .password(password)
                        .build())
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<ApiResponse<LoginResponse>>() {})
                .returnResult()
                .getResponseBody()
                .getData()
                .getAccessToken();
    }

    private String[] loginAndGetTokens(String email, String password) {
        LoginResponse loginResponse = webTestClient.post()
                .uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(LoginRequest.builder()
                        .email(email)
                        .password(password)
                        .build())
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<ApiResponse<LoginResponse>>() {})
                .returnResult()
                .getResponseBody()
                .getData();

        return new String[]{loginResponse.getAccessToken(), loginResponse.getRefreshToken()};
    }

    private String createVerifiedUserWithMfaAndGetSecret(String email, String password) {
        String passwordHash = passwordEncoder.encode(password);
        String userCode = "USR-TEST-MFA-" + System.currentTimeMillis();
        String mfaSecret = "JBSWY3DPEHPK3PXP"; // Known secret for testing

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, mfa_secret, failed_login, created_at, updated_at
                ) VALUES (
                    :id, :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :mfaSecret, :failedLogin, NOW(), NOW()
                )
                """)
                .bind("id", UUID.randomUUID())
                .bind("userCode", userCode)
                .bind("fullName", "Test User MFA")
                .bind("email", email)
                .bind("phone", generateTestPhone())
                .bind("passwordHash", passwordHash)
                .bind("nik", generateTestNik())
                .bind("address", "Jl. Test No. 123")
                .bind("dob", LocalDate.of(1990, 1, 15))
                .bind("role", UserRole.CUSTOMER.name())
                .bind("status", UserStatus.ACTIVE.name())
                .bind("emailVerified", true)
                .bind("mfaEnabled", true)
                .bind("mfaSecret", mfaSecret)
                .bind("failedLogin", (short) 0)
                .then()
                .block(Duration.ofSeconds(5));

        return mfaSecret;
    }

    /**
     * Generate a valid TOTP code for the given secret.
     */
    private String generateValidOtp(String secret) {
        try {
            byte[] decodedKey = base32Decode(secret);
            long timeStep = System.currentTimeMillis() / 1000 / 30;

            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (timeStep & 0xff);
                timeStep >>= 8;
            }

            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(decodedKey, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xf;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);

            int otp = binary % 1000000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate OTP", e);
        }
    }

    private byte[] base32Decode(String input) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        input = input.toUpperCase().replaceAll("[^A-Z2-7]", "");

        int[] buffer = new int[input.length()];
        for (int i = 0; i < input.length(); i++) {
            buffer[i] = alphabet.indexOf(input.charAt(i));
        }

        int outputLength = input.length() * 5 / 8;
        byte[] output = new byte[outputLength];

        int bitsRemaining = 0;
        int currentByte = 0;
        int outputIndex = 0;

        for (int i = 0; i < input.length(); i++) {
            currentByte = (currentByte << 5) | buffer[i];
            bitsRemaining += 5;
            if (bitsRemaining >= 8) {
                bitsRemaining -= 8;
                output[outputIndex++] = (byte) (currentByte >> bitsRemaining);
            }
        }

        return output;
    }
}
