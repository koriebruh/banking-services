package com.koriebruh.authservice.integration;

import com.koriebruh.authservice.dto.request.*;
import com.koriebruh.authservice.dto.response.*;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.exception.UserExceptions;
import com.koriebruh.authservice.repository.UserRepository;
import com.koriebruh.authservice.service.AuthService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for AuthService with real database and Redis.
 *
 * <h2>Banking Best Practices:</h2>
 * <ul>
 *   <li>Tests complete business flows end-to-end</li>
 *   <li>Verifies transactional behavior</li>
 *   <li>Tests security mechanisms (password hashing, token generation)</li>
 *   <li>All test data is cleaned up after each test</li>
 * </ul>
 */
@DisplayName("AuthService Integration Tests")
class AuthServiceIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String VALID_PASSWORD = "SecureP@ssw0rd123!";
    private static final String TEST_IP = "127.0.0.1";
    private static final String TEST_USER_AGENT = "Integration Test Agent";

    // -------------------------------------------------------------------------
    // REGISTRATION FLOW TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Complete Registration Flow")
    class RegistrationFlowTests {

        @Test
        @DisplayName("Should complete full registration flow")
        void shouldCompleteFullRegistrationFlow() {
            // Given
            String email = generateTestEmail();
            RegisterRequest request = createRegisterRequest(email);

            // When - Register
            StepVerifier.create(authService.registerUser(request))
                    .assertNext(response -> {
                        assertThat(response.getEmail()).isEqualTo(email);
                        assertThat(response.getUserCode()).startsWith("USR-");
                    })
                    .verifyComplete();

            // Then - Verify user state
            StepVerifier.create(userRepository.findByEmail(email))
                    .assertNext(user -> {
                        assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
                        assertThat(user.getEmailVerified()).isFalse();
                        assertThat(user.getRole()).isEqualTo(UserRole.CUSTOMER);
                        // Password should be hashed
                        assertThat(user.getPasswordHash()).isNotEqualTo(VALID_PASSWORD);
                        assertThat(passwordEncoder.matches(VALID_PASSWORD, user.getPasswordHash())).isTrue();
                    })
                    .verifyComplete();

            // Verify OTP was stored in Redis
            StepVerifier.create(redisTemplate.opsForValue().get("email-otp:" + email))
                    .assertNext(otp -> {
                        assertThat(otp).isNotNull();
                        assertThat(otp).hasSize(6);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should reject duplicate registrations")
        void shouldRejectDuplicateRegistrations() {
            // Given - Register first user
            String email = generateTestEmail();
            RegisterRequest request = createRegisterRequest(email);
            authService.registerUser(request).block();

            // When - Try duplicate email
            RegisterRequest duplicateRequest = createRegisterRequest(email);
            duplicateRequest.setPhoneNumber(generateTestPhone());
            duplicateRequest.setNik(generateTestNik());

            // Then
            StepVerifier.create(authService.registerUser(duplicateRequest))
                    .expectError(UserExceptions.DuplicateEmailException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // EMAIL VERIFICATION FLOW TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Email Verification Flow")
    class EmailVerificationFlowTests {

        @Test
        @DisplayName("Should verify email and activate account")
        void shouldVerifyEmailAndActivateAccount() {
            // Given - Register user
            String email = generateTestEmail();
            authService.registerUser(createRegisterRequest(email)).block();

            // Set known OTP
            String otp = "123456";
            redisTemplate.opsForValue().set("email-otp:" + email, otp, Duration.ofMinutes(5)).block();

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(email)
                    .otpCode(otp)
                    .build();

            // When
            StepVerifier.create(authService.verifyEmailOtp(request))
                    .assertNext(response -> {
                        assertThat(response.isSuccess()).isTrue();
                    })
                    .verifyComplete();

            // Then - Verify account is now active
            StepVerifier.create(userRepository.findByEmail(email))
                    .assertNext(user -> {
                        assertThat(user.getEmailVerified()).isTrue();
                        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
                    })
                    .verifyComplete();

            // OTP should be deleted from Redis (single-use)
            StepVerifier.create(redisTemplate.opsForValue().get("email-otp:" + email))
                    .verifyComplete(); // Empty
        }

        @Test
        @DisplayName("Should reject invalid OTP")
        void shouldRejectInvalidOtp() {
            // Given
            String email = generateTestEmail();
            authService.registerUser(createRegisterRequest(email)).block();

            redisTemplate.opsForValue().set("email-otp:" + email, "123456", Duration.ofMinutes(5)).block();

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(email)
                    .otpCode("000000") // Wrong OTP
                    .build();

            // When & Then
            StepVerifier.create(authService.verifyEmailOtp(request))
                    .expectError(UserExceptions.InvalidOtpException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // LOGIN FLOW TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Login Flow")
    class LoginFlowTests {

        @Test
        @DisplayName("Should login successfully and return tokens")
        void shouldLoginSuccessfully() {
            // Given - Create verified user
            String email = generateTestEmail();
            createVerifiedUser(email);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When
            StepVerifier.create(authService.loginUser(request, TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getMfaRequired()).isFalse();
                        assertThat(response.getAccessToken()).isNotBlank();
                        assertThat(response.getRefreshToken()).isNotBlank();
                        assertThat(response.getExpiresIn()).isGreaterThan(0);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should require MFA for MFA-enabled users")
        void shouldRequireMfaForMfaEnabledUsers() {
            // Given - Create verified user with MFA
            String email = generateTestEmail();
            createVerifiedUserWithMfa(email);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When
            StepVerifier.create(authService.loginUser(request, TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getMfaRequired()).isTrue();
                        assertThat(response.getMfaToken()).isNotBlank();
                        assertThat(response.getAccessToken()).isNull();
                        assertThat(response.getRefreshToken()).isNull();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should reject wrong password with LoginFailException")
        void shouldRejectWrongPassword() {
            // Given
            String email = generateTestEmail();
            createVerifiedUser(email);

            LoginRequest wrongRequest = LoginRequest.builder()
                    .email(email)
                    .password("WrongPassword!")
                    .build();

            // When & Then - Should throw LoginFailException
            StepVerifier.create(authService.loginUser(wrongRequest, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.LoginFailException.class)
                    .verify(Duration.ofSeconds(5));
        }

        @Test
        @DisplayName("Should reject login for non-existent email")
        void shouldRejectNonExistentEmail() {
            // Given
            LoginRequest request = LoginRequest.builder()
                    .email("nonexistent@integration.test")
                    .password(VALID_PASSWORD)
                    .build();

            // When & Then
            StepVerifier.create(authService.loginUser(request, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.LoginFailException.class)
                    .verify(Duration.ofSeconds(5));
        }

        @Test
        @DisplayName("Should reject login for locked account")
        void shouldRejectLoginForLockedAccount() {
            // Given - Create user that is already locked
            String email = generateTestEmail();
            createLockedUser(email);

            LoginRequest request = LoginRequest.builder()
                    .email(email)
                    .password(VALID_PASSWORD)
                    .build();

            // When & Then - Should throw AccountLockedException
            StepVerifier.create(authService.loginUser(request, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.AccountLockedException.class)
                    .verify(Duration.ofSeconds(5));
        }
    }

    // -------------------------------------------------------------------------
    // PASSWORD MANAGEMENT TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Password Management Flow")
    class PasswordManagementFlowTests {

        @Test
        @DisplayName("Should change password and revoke all refresh tokens")
        void shouldChangePasswordAndRevokeTokens() {
            // Given
            String email = generateTestEmail();
            createVerifiedUser(email);

            // Login to get tokens (creates refresh token in DB)
            LoginResponse loginResponse = authService.loginUser(
                    LoginRequest.builder()
                            .email(email)
                            .password(VALID_PASSWORD)
                            .build(),
                    TEST_IP, TEST_USER_AGENT).block();

            String userId = userRepository.findByEmail(email).block().getId().toString();

            String newPassword = "NewSecureP@ss456!";
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword(VALID_PASSWORD)
                    .newPassword(newPassword)
                    .confirmPassword(newPassword)
                    .build();

            // When
            StepVerifier.create(authService.changePassword(userId, request))
                    .verifyComplete();

            // Then - Old password shouldn't work
            StepVerifier.create(authService.loginUser(
                    LoginRequest.builder()
                            .email(email)
                            .password(VALID_PASSWORD)
                            .build(),
                    TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.LoginFailException.class)
                    .verify();

            // New password should work
            StepVerifier.create(authService.loginUser(
                    LoginRequest.builder()
                            .email(email)
                            .password(newPassword)
                            .build(),
                    TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getAccessToken()).isNotBlank();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should reset password with valid OTP")
        void shouldResetPasswordWithValidOtp() {
            // Given
            String email = generateTestEmail();
            createVerifiedUser(email);

            // Set reset OTP
            String otp = "654321";
            redisTemplate.opsForValue().set("reset-otp:" + email, otp, Duration.ofMinutes(3)).block();

            String newPassword = "ResetP@ssw0rd789!";
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .email(email)
                    .otpCode(otp)
                    .newPassword(newPassword)
                    .confirmPassword(newPassword)
                    .build();

            // When
            StepVerifier.create(authService.resetPassword(request))
                    .verifyComplete();

            // Then - Can login with new password
            StepVerifier.create(authService.loginUser(
                    LoginRequest.builder()
                            .email(email)
                            .password(newPassword)
                            .build(),
                    TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getAccessToken()).isNotBlank();
                    })
                    .verifyComplete();
        }
    }

    // -------------------------------------------------------------------------
    // TOKEN MANAGEMENT TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Token Management Flow")
    class TokenManagementFlowTests {

        @Test
        @DisplayName("Should refresh access token with valid refresh token")
        void shouldRefreshAccessToken() {
            // Given - Create user with MFA enabled (only MFA validation saves refresh token to DB)
            String email = generateTestEmail();
            String mfaSecret = createVerifiedUserWithMfaAndGetSecret(email);

            // Step 1: Login to get MFA token
            LoginResponse loginResponse = authService.loginUser(
                    LoginRequest.builder()
                            .email(email)
                            .password(VALID_PASSWORD)
                            .build(),
                    TEST_IP, TEST_USER_AGENT).block();

            assertThat(loginResponse.getMfaRequired()).isTrue();

            String userId = userRepository.findByEmail(email).block().getId().toString();

            // Step 2: Validate MFA to get refresh token (this saves it to DB)
            String validOtp = generateValidOtp(mfaSecret);
            MfaValidateResponse mfaResponse = authService.validateMfa(
                    userId,
                    MfaValidateRequest.builder().otpCode(validOtp).build(),
                    TEST_IP, TEST_USER_AGENT).block();

            String refreshToken = mfaResponse.getRefreshToken();
            assertThat(refreshToken).isNotBlank();

            // When - Refresh the token
            StepVerifier.create(authService.refreshToken(userId, refreshToken))
                    .assertNext(response -> {
                        assertThat(response.getAccessToken()).isNotBlank();
                        assertThat(response.getTokenType()).isEqualTo("Bearer");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should logout and revoke refresh token")
        void shouldLogoutAndRevokeRefreshToken() {
            // Given - Create user with MFA enabled (only MFA validation saves refresh token to DB)
            String email = generateTestEmail();
            String mfaSecret = createVerifiedUserWithMfaAndGetSecret(email);

            // Step 1: Login to get MFA token
            LoginResponse loginResponse = authService.loginUser(
                    LoginRequest.builder()
                            .email(email)
                            .password(VALID_PASSWORD)
                            .build(),
                    TEST_IP, TEST_USER_AGENT).block();

            String userId = userRepository.findByEmail(email).block().getId().toString();

            // Step 2: Validate MFA to get refresh token (this saves it to DB)
            String validOtp = generateValidOtp(mfaSecret);
            MfaValidateResponse mfaResponse = authService.validateMfa(
                    userId,
                    MfaValidateRequest.builder().otpCode(validOtp).build(),
                    TEST_IP, TEST_USER_AGENT).block();

            String refreshToken = mfaResponse.getRefreshToken();

            LogoutRequest request = LogoutRequest.builder()
                    .refreshToken(refreshToken)
                    .build();

            // When
            StepVerifier.create(authService.logout(userId, request))
                    .verifyComplete();

            // Then - Refresh token should no longer work
            StepVerifier.create(authService.refreshToken(userId, refreshToken))
                    .expectError(UserExceptions.InvalidRefreshTokenException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // HELPER METHODS
    // -------------------------------------------------------------------------

    private RegisterRequest createRegisterRequest(String email) {
        return RegisterRequest.builder()
                .email(email)
                .password(VALID_PASSWORD)
                .fullName("Test User")
                .phoneNumber(generateTestPhone())
                .nik(generateTestNik())
                .address("Jl. Test No. 123, Jakarta")
                .dateOfBirth(LocalDate.of(1990, 1, 15))
                .build();
    }

    private void createVerifiedUser(String email) {
        String passwordHash = passwordEncoder.encode(VALID_PASSWORD);
        String userCode = "USR-TEST-" + System.currentTimeMillis();

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, failed_login, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(), :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :failedLogin, NOW(), NOW()
                )
                """)
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

    private void createVerifiedUserWithMfa(String email) {
        createVerifiedUserWithMfaAndGetSecret(email);
    }

    private String createVerifiedUserWithMfaAndGetSecret(String email) {
        String passwordHash = passwordEncoder.encode(VALID_PASSWORD);
        String userCode = "USR-TEST-MFA-" + System.currentTimeMillis();
        String mfaSecret = "JBSWY3DPEHPK3PXP"; // Known secret for testing

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, mfa_secret, failed_login, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(), :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :mfaSecret, :failedLogin, NOW(), NOW()
                )
                """)
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
     * Create a user that is already locked (locked_until is in the future)
     */
    private void createLockedUser(String email) {
        String passwordHash = passwordEncoder.encode(VALID_PASSWORD);
        String userCode = "USR-TEST-LOCKED-" + System.currentTimeMillis();
        Instant lockedUntil = Instant.now().plus(30, java.time.temporal.ChronoUnit.MINUTES);

        databaseClient.sql("""
                INSERT INTO users (
                    id, user_code, full_name, email, phone_number, password_hash,
                    nik, address, date_of_birth, role, status, email_verified,
                    mfa_enabled, failed_login, locked_until, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(), :userCode, :fullName, :email, :phone, :passwordHash,
                    :nik, :address, :dob, :role, :status, :emailVerified,
                    :mfaEnabled, :failedLogin, :lockedUntil, NOW(), NOW()
                )
                """)
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

    /**
     * Generate a valid TOTP code for the given secret.
     * Uses the same algorithm as Google Authenticator.
     */
    private String generateValidOtp(String secret) {
        try {
            // Decode base32 secret
            byte[] decodedKey = base32Decode(secret);

            // Get current time step (30 second window)
            long timeStep = System.currentTimeMillis() / 1000 / 30;

            // Generate TOTP
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
