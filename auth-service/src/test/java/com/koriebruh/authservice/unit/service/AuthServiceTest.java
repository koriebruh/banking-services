package com.koriebruh.authservice.unit.service;

import com.koriebruh.authservice.dto.mapper.UserMapper;
import com.koriebruh.authservice.dto.request.*;
import com.koriebruh.authservice.dto.response.*;
import com.koriebruh.authservice.entity.RefreshToken;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.event.AuthEventPublisher;
import com.koriebruh.authservice.exception.UserExceptions;
import com.koriebruh.authservice.repository.RefreshTokenRepository;
import com.koriebruh.authservice.repository.UserRepository;
import com.koriebruh.authservice.service.AuthService;
import com.koriebruh.authservice.service.EmailOtpService;
import com.koriebruh.authservice.service.EmailService;
import com.koriebruh.authservice.service.OtpService;
import com.koriebruh.authservice.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Unit Tests")
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserMapper userMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private TransactionalOperator transactionalOperator;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private EmailOtpService emailOtpService;

    @Mock
    private OtpService otpService;

    @Mock
    private AuthEventPublisher eventPublisher;

    private AuthService authService;

    private User testUser;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "Password123!";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                userRepository,
                userMapper,
                passwordEncoder,
                transactionalOperator,
                jwtUtil,
                refreshTokenRepository,
                emailService,
                emailOtpService,
                otpService,
                eventPublisher
        );

        testUser = User.builder()
                .id(UUID.randomUUID())
                .userCode("USR-20260302-00001")
                .email(TEST_EMAIL)
                .fullName("Test User")
                .phoneNumber("081234567890")
                .passwordHash("hashedPassword")
                .nik("1234567890123456")
                .address("Test Address")
                .dateOfBirth(LocalDate.of(1990, 1, 1))
                .role(UserRole.CUSTOMER)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .mfaEnabled(false)
                .mfaSecret(null)
                .failedLogin((short) 0)
                .build();

        // Default transactional operator behavior
        lenient().when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    // -------------------------------------------------------------------------
    // REGISTRATION TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("User Registration")
    class UserRegistration {

        private RegisterRequest registerRequest;

        @BeforeEach
        void setUp() {
            registerRequest = RegisterRequest.builder()
                    .email(TEST_EMAIL)
                    .password(TEST_PASSWORD)
                    .fullName("Test User")
                    .phoneNumber("081234567890")
                    .nik("1234567890123456")
                    .address("Test Address")
                    .dateOfBirth(LocalDate.of(1990, 1, 1))
                    .build();
        }

        @Test
        @DisplayName("Should register user successfully")
        void shouldRegisterUserSuccessfully() {
            // Given
            when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(Mono.just(false));
            when(userRepository.existsByNik(anyString())).thenReturn(Mono.just(false));
            when(userRepository.existsByPhoneNumber(anyString())).thenReturn(Mono.just(false));
            when(userRepository.getNextSequence()).thenReturn(Mono.just(1L));
            when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));
            when(userMapper.toRegisterResponse(any(User.class))).thenReturn(
                    RegisterResponse.builder()
                            .userCode(testUser.getUserCode())
                            .email(testUser.getEmail())
                            .fullName(testUser.getFullName())
                            .build()
            );
            when(emailOtpService.generateAndStoreOtp(TEST_EMAIL)).thenReturn(Mono.just("123456"));
            when(emailService.sendVerificationOtp(TEST_EMAIL, "123456")).thenReturn(Mono.empty());
            when(eventPublisher.publish(any(), anyString(), anyString(), any(), any(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.registerUser(registerRequest))
                    .assertNext(response -> {
                        assertThat(response.getUserCode()).isEqualTo(testUser.getUserCode());
                        assertThat(response.getEmail()).isEqualTo(testUser.getEmail());
                    })
                    .verifyComplete();

            // Then
            verify(userRepository).save(any(User.class));
            verify(emailOtpService).generateAndStoreOtp(TEST_EMAIL);
            verify(emailService).sendVerificationOtp(eq(TEST_EMAIL), anyString());
        }

        @Test
        @DisplayName("Should fail registration when email already exists")
        void shouldFailWhenEmailExists() {
            // Given
            when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(Mono.just(true));
            when(userRepository.existsByNik(anyString())).thenReturn(Mono.just(false));
            when(userRepository.existsByPhoneNumber(anyString())).thenReturn(Mono.just(false));
            // Need to mock getNextSequence because .then() chain requires non-null Mono
            when(userRepository.getNextSequence()).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(authService.registerUser(registerRequest))
                    .expectError(UserExceptions.DuplicateEmailException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail registration when NIK already exists")
        void shouldFailWhenNikExists() {
            // Given
            when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(Mono.just(false));
            when(userRepository.existsByNik(anyString())).thenReturn(Mono.just(true));
            when(userRepository.existsByPhoneNumber(anyString())).thenReturn(Mono.just(false));
            // Need to mock getNextSequence because .then() chain requires non-null Mono
            when(userRepository.getNextSequence()).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(authService.registerUser(registerRequest))
                    .expectError(UserExceptions.DuplicateNikException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail registration when phone number already exists")
        void shouldFailWhenPhoneExists() {
            // Given
            when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(Mono.just(false));
            when(userRepository.existsByNik(anyString())).thenReturn(Mono.just(false));
            when(userRepository.existsByPhoneNumber(anyString())).thenReturn(Mono.just(true));
            // Need to mock getNextSequence because .then() chain requires non-null Mono
            when(userRepository.getNextSequence()).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(authService.registerUser(registerRequest))
                    .expectError(UserExceptions.DuplicatePhoneNumberException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // EMAIL VERIFICATION TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Email Verification")
    class EmailVerification {

        @Test
        @DisplayName("Should verify email successfully")
        void shouldVerifyEmailSuccessfully() {
            // Given
            User unverifiedUser = testUser.toBuilder()
                    .emailVerified(false)
                    .status(UserStatus.PENDING_VERIFICATION)
                    .build();

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("123456")
                    .build();

            when(emailOtpService.verifyOtp(TEST_EMAIL, "123456")).thenReturn(Mono.just(true));
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(unverifiedUser));
            when(userRepository.verifyUserEmail(any(UUID.class), any(Instant.class))).thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.verifyEmailOtp(request))
                    .assertNext(response -> {
                        assertThat(response.isSuccess()).isTrue();
                        assertThat(response.getMessage()).contains("verified");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should fail verification with invalid OTP")
        void shouldFailWithInvalidOtp() {
            // Given
            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("000000")
                    .build();

            when(emailOtpService.verifyOtp(TEST_EMAIL, "000000")).thenReturn(Mono.just(false));

            // When/Then
            StepVerifier.create(authService.verifyEmailOtp(request))
                    .expectError(UserExceptions.InvalidOtpException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail when email already verified")
        void shouldFailWhenAlreadyVerified() {
            // Given
            User verifiedUser = testUser.toBuilder().emailVerified(true).build();

            VerifyEmailOtpRequest request = VerifyEmailOtpRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("123456")
                    .build();

            when(emailOtpService.verifyOtp(TEST_EMAIL, "123456")).thenReturn(Mono.just(true));
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(verifiedUser));

            // When/Then
            StepVerifier.create(authService.verifyEmailOtp(request))
                    .expectError(UserExceptions.EmailAlreadyVerifiedException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // LOGIN TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("User Login")
    class UserLogin {

        private LoginRequest loginRequest;

        @BeforeEach
        void setUp() {
            loginRequest = LoginRequest.builder()
                    .email(TEST_EMAIL)
                    .password(TEST_PASSWORD)
                    .build();
        }

        @Test
        @DisplayName("Should login successfully without MFA")
        void shouldLoginSuccessfullyWithoutMfa() {
            // Given
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches(TEST_PASSWORD, testUser.getPasswordHash())).thenReturn(true);
            when(userRepository.updateFailedLoginAttempts(any(UUID.class), eq((short) 0), any(Instant.class)))
                    .thenReturn(Mono.empty());
            when(jwtUtil.generateAccessToken(testUser)).thenReturn("access-token");
            when(jwtUtil.generateRefreshToken(testUser)).thenReturn("refresh-token");
            when(jwtUtil.getAccessTokenExpirationInSeconds()).thenReturn(900L);
            when(jwtUtil.getRefreshTokenExpirationInSeconds()).thenReturn(604800L);
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(Mono.just(RefreshToken.builder().build()));
            when(userRepository.updateSuccessfulLogin(any(UUID.class), any(Instant.class))).thenReturn(Mono.empty());
            when(eventPublisher.publish(any(), anyString(), anyString(), anyString(), anyString(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.loginUser(loginRequest, TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getMfaRequired()).isFalse();
                        assertThat(response.getAccessToken()).isEqualTo("access-token");
                        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should return MFA token when MFA is enabled")
        void shouldReturnMfaTokenWhenMfaEnabled() {
            // Given
            User mfaUser = testUser.toBuilder().mfaEnabled(true).mfaSecret("secret").build();

            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(mfaUser));
            when(passwordEncoder.matches(TEST_PASSWORD, mfaUser.getPasswordHash())).thenReturn(true);
            when(userRepository.updateFailedLoginAttempts(any(UUID.class), eq((short) 0), any(Instant.class)))
                    .thenReturn(Mono.empty());
            when(jwtUtil.generateMfaToken(mfaUser)).thenReturn("mfa-token");
            when(jwtUtil.getMfaTokenExpirationInSeconds()).thenReturn(300L);
            when(eventPublisher.publish(any(), anyString(), anyString(), anyString(), anyString(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.loginUser(loginRequest, TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getMfaRequired()).isTrue();
                        assertThat(response.getMfaToken()).isEqualTo("mfa-token");
                        assertThat(response.getAccessToken()).isNull();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should fail login with wrong password")
        void shouldFailWithWrongPassword() {
            // Given
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches(TEST_PASSWORD, testUser.getPasswordHash())).thenReturn(false);
            when(userRepository.updateFailedLoginAttempts(any(UUID.class), any(Short.class), any(Instant.class)))
                    .thenReturn(Mono.empty());

            // When/Then
            StepVerifier.create(authService.loginUser(loginRequest, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.LoginFailException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail login with non-existent email")
        void shouldFailWithNonExistentEmail() {
            // Given
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.empty());

            // When/Then
            StepVerifier.create(authService.loginUser(loginRequest, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.LoginFailException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail login when account is locked")
        void shouldFailWhenAccountLocked() {
            // Given
            User lockedUser = testUser.toBuilder()
                    .lockedUntil(Instant.now().plus(10, ChronoUnit.MINUTES))
                    .build();

            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(lockedUser));

            // When/Then
            StepVerifier.create(authService.loginUser(loginRequest, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.AccountLockedException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail login when user is not active")
        void shouldFailWhenUserNotActive() {
            // Given
            User pendingUser = testUser.toBuilder().status(UserStatus.PENDING_VERIFICATION).build();

            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(pendingUser));
            when(passwordEncoder.matches(TEST_PASSWORD, pendingUser.getPasswordHash())).thenReturn(true);

            // When/Then
            StepVerifier.create(authService.loginUser(loginRequest, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.UnactivatedException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // MFA SETUP TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("MFA Setup")
    class MfaSetup {

        @Test
        @DisplayName("Should setup MFA successfully")
        void shouldSetupMfaSuccessfully() throws Exception {
            // Given
            String userId = testUser.getId().toString();

            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));
            when(otpService.generateSecret()).thenReturn("secret123");
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));
            when(otpService.generateQrCodeBase64(testUser.getEmail(), "secret123")).thenReturn("base64qrcode");

            // When
            StepVerifier.create(authService.setupMfa(userId))
                    .assertNext(response -> {
                        assertThat(response.getQrCode()).isEqualTo("base64qrcode");
                        assertThat(response.getSecret()).isEqualTo("secret123");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should fail MFA setup when email not verified")
        void shouldFailMfaSetupWhenEmailNotVerified() {
            // Given
            User unverifiedUser = testUser.toBuilder().emailVerified(false).build();
            String userId = unverifiedUser.getId().toString();

            when(userRepository.findById(unverifiedUser.getId())).thenReturn(Mono.just(unverifiedUser));

            // When/Then
            StepVerifier.create(authService.setupMfa(userId))
                    .expectError(UserExceptions.EmailNotVerifiedException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail MFA setup when MFA already enabled")
        void shouldFailMfaSetupWhenAlreadyEnabled() {
            // Given
            User mfaEnabledUser = testUser.toBuilder().mfaEnabled(true).build();
            String userId = mfaEnabledUser.getId().toString();

            when(userRepository.findById(mfaEnabledUser.getId())).thenReturn(Mono.just(mfaEnabledUser));

            // When/Then
            StepVerifier.create(authService.setupMfa(userId))
                    .expectError(UserExceptions.MfaAlreadyEnabledException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // MFA VERIFY SETUP TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("MFA Setup Verification")
    class MfaSetupVerification {

        @Test
        @DisplayName("Should verify MFA setup successfully")
        void shouldVerifyMfaSetupSuccessfully() {
            // Given
            User userWithSecret = testUser.toBuilder().mfaSecret("secret123").mfaEnabled(false).build();
            String userId = userWithSecret.getId().toString();

            MfaSetupVerifyRequest request = MfaSetupVerifyRequest.builder()
                    .otpCode("123456")
                    .build();

            when(userRepository.findById(userWithSecret.getId())).thenReturn(Mono.just(userWithSecret));
            when(otpService.verifyOtp("secret123", "123456")).thenReturn(true);
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(userWithSecret.toBuilder().mfaEnabled(true).build()));
            when(eventPublisher.publish(any(), anyString(), anyString(), any(), any(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.verifyMfaSetup(userId, request))
                    .assertNext(response -> {
                        assertThat(response.getMfaEnabled()).isTrue();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should fail MFA verify when no secret found")
        void shouldFailMfaVerifyWhenNoSecret() {
            // Given
            User userWithoutSecret = testUser.toBuilder().mfaSecret(null).build();
            String userId = userWithoutSecret.getId().toString();

            MfaSetupVerifyRequest request = MfaSetupVerifyRequest.builder()
                    .otpCode("123456")
                    .build();

            when(userRepository.findById(userWithoutSecret.getId())).thenReturn(Mono.just(userWithoutSecret));

            // When/Then
            StepVerifier.create(authService.verifyMfaSetup(userId, request))
                    .expectError(UserExceptions.MfaNotSetupException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail MFA verify with invalid OTP")
        void shouldFailMfaVerifyWithInvalidOtp() {
            // Given
            User userWithSecret = testUser.toBuilder().mfaSecret("secret123").mfaEnabled(false).build();
            String userId = userWithSecret.getId().toString();

            MfaSetupVerifyRequest request = MfaSetupVerifyRequest.builder()
                    .otpCode("000000")
                    .build();

            when(userRepository.findById(userWithSecret.getId())).thenReturn(Mono.just(userWithSecret));
            when(otpService.verifyOtp("secret123", "000000")).thenReturn(false);

            // When/Then
            StepVerifier.create(authService.verifyMfaSetup(userId, request))
                    .expectError(UserExceptions.InvalidOtpException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // MFA VALIDATE TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("MFA Validation")
    class MfaValidation {

        @Test
        @DisplayName("Should validate MFA successfully and return tokens")
        void shouldValidateMfaSuccessfully() {
            // Given
            User mfaUser = testUser.toBuilder().mfaEnabled(true).mfaSecret("secret123").build();
            String userId = mfaUser.getId().toString();

            MfaValidateRequest request = MfaValidateRequest.builder()
                    .otpCode("123456")
                    .build();

            when(userRepository.findById(mfaUser.getId())).thenReturn(Mono.just(mfaUser));
            when(otpService.verifyOtp("secret123", "123456")).thenReturn(true);
            when(jwtUtil.generateAccessToken(mfaUser)).thenReturn("access-token");
            when(jwtUtil.generateRefreshToken(mfaUser)).thenReturn("refresh-token");
            when(jwtUtil.getRefreshTokenExpirationInSeconds()).thenReturn(604800L);
            when(jwtUtil.getAccessTokenExpirationInSeconds()).thenReturn(900L);
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(Mono.just(RefreshToken.builder().build()));
            when(userRepository.updateSuccessfulLogin(any(UUID.class), any(Instant.class))).thenReturn(Mono.empty());
            when(eventPublisher.publish(any(), anyString(), anyString(), anyString(), anyString(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.validateMfa(userId, request, TEST_IP, TEST_USER_AGENT))
                    .assertNext(response -> {
                        assertThat(response.getAccessToken()).isEqualTo("access-token");
                        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
                        assertThat(response.getTokenType()).isEqualTo("Bearer");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should fail MFA validation when MFA not enabled")
        void shouldFailMfaValidationWhenNotEnabled() {
            // Given
            String userId = testUser.getId().toString();

            MfaValidateRequest request = MfaValidateRequest.builder()
                    .otpCode("123456")
                    .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));

            // When/Then
            StepVerifier.create(authService.validateMfa(userId, request, TEST_IP, TEST_USER_AGENT))
                    .expectError(UserExceptions.MfaNotSetupException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // LOGOUT TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Logout")
    class Logout {

        @Test
        @DisplayName("Should logout successfully")
        void shouldLogoutSuccessfully() {
            // Given
            String userId = testUser.getId().toString();
            String refreshToken = "refresh-token";

            LogoutRequest request = LogoutRequest.builder()
                    .refreshToken(refreshToken)
                    .build();

            RefreshToken storedToken = RefreshToken.builder()
                    .userId(testUser.getId())
                    .tokenHash("hashed-token")
                    .build();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.just(storedToken));
            when(refreshTokenRepository.revokeToken(anyString(), any(Instant.class)))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.logout(userId, request))
                    .verifyComplete();

            // Then
            verify(refreshTokenRepository).revokeToken(anyString(), any(Instant.class));
        }

        @Test
        @DisplayName("Should fail logout with invalid refresh token")
        void shouldFailLogoutWithInvalidToken() {
            // Given
            String userId = testUser.getId().toString();

            LogoutRequest request = LogoutRequest.builder()
                    .refreshToken("invalid-token")
                    .build();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.empty());

            // When/Then
            StepVerifier.create(authService.logout(userId, request))
                    .expectError(UserExceptions.InvalidRefreshTokenException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail logout when token belongs to different user")
        void shouldFailLogoutWhenTokenBelongsToDifferentUser() {
            // Given
            String userId = testUser.getId().toString();

            LogoutRequest request = LogoutRequest.builder()
                    .refreshToken("refresh-token")
                    .build();

            RefreshToken storedToken = RefreshToken.builder()
                    .userId(UUID.randomUUID()) // Different user
                    .tokenHash("hashed-token")
                    .build();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.just(storedToken));

            // When/Then
            StepVerifier.create(authService.logout(userId, request))
                    .expectError(UserExceptions.InvalidRefreshTokenException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // PASSWORD CHANGE TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Change Password")
    class ChangePassword {

        @Test
        @DisplayName("Should change password successfully")
        void shouldChangePasswordSuccessfully() {
            // Given
            String userId = testUser.getId().toString();

            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword(TEST_PASSWORD)
                    .newPassword("NewPassword123!")
                    .confirmPassword("NewPassword123!")
                    .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches(TEST_PASSWORD, testUser.getPasswordHash())).thenReturn(true);
            when(passwordEncoder.matches("NewPassword123!", testUser.getPasswordHash())).thenReturn(false);
            when(passwordEncoder.encode("NewPassword123!")).thenReturn("newHashedPassword");
            when(userRepository.updatePassword(any(UUID.class), anyString(), any(Instant.class)))
                    .thenReturn(Mono.empty());
            when(refreshTokenRepository.revokeAllUserTokens(any(UUID.class), any(Instant.class)))
                    .thenReturn(Mono.empty());
            when(eventPublisher.publish(any(), anyString(), anyString(), any(), any(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.changePassword(userId, request))
                    .verifyComplete();

            // Then
            verify(userRepository).updatePassword(any(UUID.class), eq("newHashedPassword"), any(Instant.class));
            verify(refreshTokenRepository).revokeAllUserTokens(any(UUID.class), any(Instant.class));
        }

        @Test
        @DisplayName("Should fail change password with wrong current password")
        void shouldFailWithWrongCurrentPassword() {
            // Given
            String userId = testUser.getId().toString();

            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword("WrongPassword")
                    .newPassword("NewPassword123!")
                    .confirmPassword("NewPassword123!")
                    .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches("WrongPassword", testUser.getPasswordHash())).thenReturn(false);

            // When/Then
            StepVerifier.create(authService.changePassword(userId, request))
                    .expectError(UserExceptions.InvalidCurrentPasswordException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail when new password is same as current")
        void shouldFailWhenNewPasswordSameAsCurrent() {
            // Given
            String userId = testUser.getId().toString();

            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword(TEST_PASSWORD)
                    .newPassword(TEST_PASSWORD)
                    .confirmPassword(TEST_PASSWORD)
                    .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches(TEST_PASSWORD, testUser.getPasswordHash())).thenReturn(true);

            // When/Then
            StepVerifier.create(authService.changePassword(userId, request))
                    .expectError(UserExceptions.SamePasswordException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail when confirm password does not match")
        void shouldFailWhenConfirmPasswordDoesNotMatch() {
            // Given
            String userId = testUser.getId().toString();

            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword(TEST_PASSWORD)
                    .newPassword("NewPassword123!")
                    .confirmPassword("DifferentPassword123!")
                    .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches(TEST_PASSWORD, testUser.getPasswordHash())).thenReturn(true);
            when(passwordEncoder.matches("NewPassword123!", testUser.getPasswordHash())).thenReturn(false);

            // When/Then
            StepVerifier.create(authService.changePassword(userId, request))
                    .expectError(UserExceptions.PasswordMismatchException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // FORGOT PASSWORD TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Forgot Password")
    class ForgotPassword {

        @Test
        @DisplayName("Should send reset OTP for existing user")
        void shouldSendResetOtpForExistingUser() {
            // Given
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .email(TEST_EMAIL)
                    .build();

            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));
            when(emailOtpService.generateAndStoreResetOtp(TEST_EMAIL)).thenReturn(Mono.just("123456"));
            when(emailService.sendResetPasswordOtp(TEST_EMAIL, "123456")).thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.forgotPassword(request))
                    .verifyComplete();

            // Then
            verify(emailOtpService).generateAndStoreResetOtp(TEST_EMAIL);
            verify(emailService).sendResetPasswordOtp(TEST_EMAIL, "123456");
        }

        @Test
        @DisplayName("Should complete without error for non-existent email")
        void shouldCompleteForNonExistentEmail() {
            // Given
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .email("nonexistent@example.com")
                    .build();

            when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.forgotPassword(request))
                    .verifyComplete();

            // Then - No email should be sent
            verify(emailOtpService, never()).generateAndStoreResetOtp(anyString());
        }
    }

    // -------------------------------------------------------------------------
    // RESET PASSWORD TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Reset Password")
    class ResetPassword {

        @Test
        @DisplayName("Should reset password successfully")
        void shouldResetPasswordSuccessfully() {
            // Given
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("123456")
                    .newPassword("NewPassword123!")
                    .confirmPassword("NewPassword123!")
                    .build();

            when(emailOtpService.verifyResetOtp(TEST_EMAIL, "123456")).thenReturn(Mono.just(true));
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches("NewPassword123!", testUser.getPasswordHash())).thenReturn(false);
            when(passwordEncoder.encode("NewPassword123!")).thenReturn("newHashedPassword");
            when(userRepository.updatePassword(any(UUID.class), anyString(), any(Instant.class)))
                    .thenReturn(Mono.empty());
            when(refreshTokenRepository.revokeAllUserTokens(any(UUID.class), any(Instant.class)))
                    .thenReturn(Mono.empty());
            when(eventPublisher.publish(any(), anyString(), anyString(), any(), any(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.resetPassword(request))
                    .verifyComplete();

            // Then
            verify(userRepository).updatePassword(any(UUID.class), eq("newHashedPassword"), any(Instant.class));
        }

        @Test
        @DisplayName("Should fail reset with invalid OTP")
        void shouldFailResetWithInvalidOtp() {
            // Given
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("000000")
                    .newPassword("NewPassword123!")
                    .confirmPassword("NewPassword123!")
                    .build();

            when(emailOtpService.verifyResetOtp(TEST_EMAIL, "000000")).thenReturn(Mono.just(false));

            // When/Then
            StepVerifier.create(authService.resetPassword(request))
                    .expectError(UserExceptions.InvalidOtpException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail reset when passwords do not match")
        void shouldFailResetWhenPasswordsDoNotMatch() {
            // Given
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("123456")
                    .newPassword("NewPassword123!")
                    .confirmPassword("DifferentPassword!")
                    .build();

            when(emailOtpService.verifyResetOtp(TEST_EMAIL, "123456")).thenReturn(Mono.just(true));
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));

            // When/Then
            StepVerifier.create(authService.resetPassword(request))
                    .expectError(UserExceptions.PasswordMismatchException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail reset when new password same as current")
        void shouldFailResetWhenNewPasswordSameAsCurrent() {
            // Given
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .email(TEST_EMAIL)
                    .otpCode("123456")
                    .newPassword(TEST_PASSWORD)
                    .confirmPassword(TEST_PASSWORD)
                    .build();

            when(emailOtpService.verifyResetOtp(TEST_EMAIL, "123456")).thenReturn(Mono.just(true));
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));
            when(passwordEncoder.matches(TEST_PASSWORD, testUser.getPasswordHash())).thenReturn(true);

            // When/Then
            StepVerifier.create(authService.resetPassword(request))
                    .expectError(UserExceptions.SamePasswordException.class)
                    .verify();
        }
    }

    // -------------------------------------------------------------------------
    // RESEND VERIFICATION TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Resend Verification")
    class ResendVerification {

        @Test
        @DisplayName("Should resend verification for pending user")
        void shouldResendVerificationForPendingUser() {
            // Given
            User pendingUser = testUser.toBuilder()
                    .emailVerified(false)
                    .status(UserStatus.PENDING_VERIFICATION)
                    .build();

            ResendVerificationRequest request = ResendVerificationRequest.builder()
                    .email(TEST_EMAIL)
                    .build();

            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(pendingUser));
            when(emailOtpService.generateAndStoreOtp(TEST_EMAIL)).thenReturn(Mono.just("123456"));
            when(emailService.sendVerificationOtp(TEST_EMAIL, "123456")).thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.resendVerification(request))
                    .verifyComplete();

            // Then
            verify(emailOtpService).generateAndStoreOtp(TEST_EMAIL);
            verify(emailService).sendVerificationOtp(TEST_EMAIL, "123456");
        }

        @Test
        @DisplayName("Should skip resend for already verified user")
        void shouldSkipResendForVerifiedUser() {
            // Given
            ResendVerificationRequest request = ResendVerificationRequest.builder()
                    .email(TEST_EMAIL)
                    .build();

            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(testUser));

            // When
            StepVerifier.create(authService.resendVerification(request))
                    .verifyComplete();

            // Then - No OTP should be generated
            verify(emailOtpService, never()).generateAndStoreOtp(anyString());
        }

        @Test
        @DisplayName("Should complete for non-existent email (no enumeration)")
        void shouldCompleteForNonExistentEmail() {
            // Given
            ResendVerificationRequest request = ResendVerificationRequest.builder()
                    .email("nonexistent@example.com")
                    .build();

            when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Mono.empty());

            // When
            StepVerifier.create(authService.resendVerification(request))
                    .verifyComplete();
        }
    }

    // -------------------------------------------------------------------------
    // REFRESH TOKEN TESTS
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Refresh Token")
    class RefreshTokenTests {

        @Test
        @DisplayName("Should refresh token successfully")
        void shouldRefreshTokenSuccessfully() {
            // Given
            String userId = testUser.getId().toString();
            String rawRefreshToken = "raw-refresh-token";

            RefreshToken storedToken = RefreshToken.builder()
                    .userId(testUser.getId())
                    .tokenHash("hashed-token")
                    .build();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.just(storedToken));
            when(userRepository.findById(testUser.getId())).thenReturn(Mono.just(testUser));
            when(jwtUtil.generateAccessToken(testUser)).thenReturn("new-access-token");
            when(jwtUtil.getAccessTokenExpirationInSeconds()).thenReturn(900L);

            // When
            StepVerifier.create(authService.refreshToken(userId, rawRefreshToken))
                    .assertNext(response -> {
                        assertThat(response.getAccessToken()).isEqualTo("new-access-token");
                        assertThat(response.getTokenType()).isEqualTo("Bearer");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should fail refresh with invalid token")
        void shouldFailRefreshWithInvalidToken() {
            // Given
            String userId = testUser.getId().toString();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.empty());

            // When/Then
            StepVerifier.create(authService.refreshToken(userId, "invalid-token"))
                    .expectError(UserExceptions.InvalidRefreshTokenException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail refresh when token belongs to different user")
        void shouldFailRefreshWhenTokenBelongsToDifferentUser() {
            // Given
            String userId = testUser.getId().toString();

            RefreshToken storedToken = RefreshToken.builder()
                    .userId(UUID.randomUUID()) // Different user
                    .tokenHash("hashed-token")
                    .build();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.just(storedToken));

            // When/Then
            StepVerifier.create(authService.refreshToken(userId, "refresh-token"))
                    .expectError(UserExceptions.InvalidRefreshTokenException.class)
                    .verify();
        }

        @Test
        @DisplayName("Should fail refresh when user is not active")
        void shouldFailRefreshWhenUserNotActive() {
            // Given
            User inactiveUser = testUser.toBuilder().status(UserStatus.SUSPENDED).build();
            String userId = inactiveUser.getId().toString();

            RefreshToken storedToken = RefreshToken.builder()
                    .userId(inactiveUser.getId())
                    .tokenHash("hashed-token")
                    .build();

            when(refreshTokenRepository.findValidTokenByHash(anyString(), any(Instant.class)))
                    .thenReturn(Mono.just(storedToken));
            when(userRepository.findById(inactiveUser.getId())).thenReturn(Mono.just(inactiveUser));

            // When/Then
            StepVerifier.create(authService.refreshToken(userId, "refresh-token"))
                    .expectError(UserExceptions.LoginFailException.class)
                    .verify();
        }
    }
}


