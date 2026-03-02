package com.koriebruh.authservice.service;

import com.koriebruh.authservice.dto.mapper.UserMapper;
import com.koriebruh.authservice.dto.request.*;
import com.koriebruh.authservice.dto.response.*;
import com.koriebruh.authservice.entity.RefreshToken;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.event.AuthEventPublisher;
import com.koriebruh.authservice.event.AuthEventType;
import com.koriebruh.authservice.exception.UserExceptions;
import com.koriebruh.authservice.repository.RefreshTokenRepository;
import com.koriebruh.authservice.repository.UserRepository;
import com.koriebruh.authservice.util.JwtUtil;
import dev.samstevens.totp.exceptions.QrGenerationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final PasswordEncoder passwordEncoder;

    private final TransactionalOperator transactionalOperator;

    private final JwtUtil jwtUtil;

    private final RefreshTokenRepository refreshTokenRepository;

    private final EmailService emailService;

    private final EmailOtpService emailOtpService;

    private final OtpService otpService;

    private static final short MAX_FAILED_ATTEMPTS = 5;

    private static final long LOCK_DURATION_MINUTES = 15;

    private final AuthEventPublisher eventPublisher;

    // -------------------------------------------------------------------------
    // REGISTRATION
    // -------------------------------------------------------------------------

    /**
     * Registers a new user using a fully reactive flow (WebFlux + R2DBC).
     *
     * <p>Flow:
     * <ol>
     *   <li>Validate unique fields asynchronously in parallel (email, NIK, phone)</li>
     *   <li>Generate a business {@code userCode} from the database sequence</li>
     *   <li>Build the user entity and hash the password</li>
     *   <li>Persist the user inside a reactive transaction</li>
     *   <li>Send an email OTP for address verification</li>
     *   <li>Map to response DTO</li>
     * </ol>
     *
     * <p>Notes:
     * <ul>
     *   <li>No blocking calls are allowed in this method.</li>
     *   <li>Unique constraints must still exist at the DB level as the ultimate guard against race conditions.</li>
     *   <li>Sequence gaps in {@code userCode} are acceptable and expected DB behavior.</li>
     * </ul>
     *
     * @param request registration payload
     * @return {@link RegisterResponse} containing the newly created user's details
     */
    public Mono<RegisterResponse> registerUser(RegisterRequest request) {

        return validateUniqueFieldsAsync(request)
                .then(userRepository.getNextSequence())
                // BUILD ENTITY USER
                .map(sequence -> {
                    String today = LocalDate.now()
                            .format(DateTimeFormatter.ofPattern("yyyyMMdd"));
                    String userCode = String.format("USR-%s-%05d", today, sequence);
                    log.debug("Generated userCode: {}", userCode);

                    return User.builder()
                            .userCode(userCode)
                            .fullName(request.getFullName())
                            .email(request.getEmail())
                            .phoneNumber(request.getPhoneNumber())
                            .passwordHash(passwordEncoder.encode(request.getPassword()))
                            .nik(request.getNik())
                            .address(request.getAddress())
                            .dateOfBirth(request.getDateOfBirth())
                            .role(UserRole.CUSTOMER)
                            .status(UserStatus.PENDING_VERIFICATION)
                            .emailVerified(false)
                            .mfaEnabled(false)
                            .mfaSecret(null)
                            .build();
                })
                .flatMap(userRepository::save)

                .doOnSuccess(savedUser ->
                        log.info("User registered successfully. userCode={}, role={}, status={}",
                                savedUser.getUserCode(),
                                savedUser.getRole(),
                                savedUser.getStatus())
                )

                .map(userMapper::toRegisterResponse)
                .flatMap(response ->
                        emailOtpService.generateAndStoreOtp(request.getEmail())
                                .flatMap(otp -> emailService.sendVerificationOtp(request.getEmail(), otp))
                                .then(eventPublisher.publish(
                                        AuthEventType.USER_REGISTERED,
                                        response.getUserCode(),
                                        maskEmail(request.getEmail()),
                                        null, null, null
                                ))
                                .thenReturn(response)
                )
                .as(transactionalOperator::transactional);
    }

    /**
     * Validate uniqueness of critical business fields.
     * <p>
     * This method runs existence checks in parallel using Mono.zip
     * to reduce total latency.
     * <p>
     * IMPORTANT:
     * - This is pre-validation for better user experience.
     * - Database unique constraints remain the ultimate protection
     * against race conditions.
     */
    private Mono<Void> validateUniqueFieldsAsync(RegisterRequest request) {
        Mono<Boolean> emailExistsMono = userRepository.existsByEmail(request.getEmail());
        Mono<Boolean> nikExistsMono = userRepository.existsByNik(request.getNik());
        Mono<Boolean> phoneExistsMono = userRepository.existsByPhoneNumber(request.getPhoneNumber());

        return Mono.zip(emailExistsMono, nikExistsMono, phoneExistsMono)
                .flatMap(tuple -> {

                    boolean emailExists = tuple.getT1();
                    boolean nikExists = tuple.getT2();
                    boolean phoneExists = tuple.getT3();

                    if (emailExists) {
                        log.warn("Registration failed - duplicate email: {}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.DuplicateEmailException(request.getEmail()));
                    }

                    if (nikExists) {
                        log.warn("Registration failed - duplicate NIK for email: {}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.DuplicateNikException(request.getNik()));
                    }

                    if (phoneExists) {
                        log.warn("Registration failed - duplicate phone for email: {}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.DuplicatePhoneNumberException(request.getPhoneNumber()));
                    }

                    return Mono.empty();
                });
    }


    // -------------------------------------------------------------------------
    // EMAIL VERIFICATION
    // -------------------------------------------------------------------------

    /**
     * Verifies a user's email address using the OTP that was sent on registration.
     *
     * <p>Flow:
     * <ol>
     *   <li>Look up the OTP in Redis; an absent or expired entry is treated as invalid</li>
     *   <li>Validate the supplied OTP code</li>
     *   <li>Update the user record: {@code status = ACTIVE}, {@code emailVerified = true}</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>OTP is single-use — it is deleted from Redis immediately after verification.</li>
     *   <li>OTP expires automatically after 5 minutes via Redis TTL.</li>
     *   <li>Generic error messages are used to avoid leaking information.</li>
     * </ul>
     *
     * @param request contains the email and the 6-digit OTP code
     * @return {@link VerifyEmailOtpResponse} confirming successful verification
     */
    public Mono<VerifyEmailOtpResponse> verifyEmailOtp(VerifyEmailOtpRequest request) {
        return emailOtpService.verifyOtp(request.getEmail(), request.getOtpCode())
                .flatMap(isValid -> {
                    if (!isValid) {
                        log.warn("Email verification failed - invalid or expired OTP. email={}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.InvalidOtpException());
                    }
                    return userRepository.findByEmail(request.getEmail());
                })
                .flatMap(user -> {
                    if (user.getEmailVerified()) {
                        log.warn("Email already verified. email={}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.EmailAlreadyVerifiedException());
                    }
                    return userRepository.verifyUserEmail(user.getId(), Instant.now());
                })
                .thenReturn(VerifyEmailOtpResponse.builder()
                        .success(true)
                        .message("Email verified successfully. Please proceed to MFA setup.")
                        .build())
                .doOnSuccess(v ->
                        log.info("Email verified successfully. email={}", maskEmail(request.getEmail()))
                )
                .as(transactionalOperator::transactional);
    }


    /**
     * Re-sends the email verification OTP to the given address.
     *
     * <p>Flow:
     * <ol>
     *   <li>Look up the user by email</li>
     *   <li>Skip silently if the email is already verified</li>
     *   <li>Skip silently if the account status is not {@code PENDING_VERIFICATION}</li>
     *   <li>Generate a new OTP (automatically overwrites the previous Redis entry)</li>
     *   <li>Send the OTP via email</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>Always returns success regardless of whether the email is registered (prevents user enumeration).</li>
     *   <li>This endpoint is public — no authentication token required.</li>
     * </ul>
     *
     * @param request contains the email to resend the OTP to
     * @return empty {@link Mono} on completion
     */
    public Mono<Void> resendVerification(ResendVerificationRequest request) {
        return userRepository.findByEmail(request.getEmail())
                .flatMap(user -> {

                    // SUDAH VERIFIED — tidak perlu kirim ulang
                    if (Boolean.TRUE.equals(user.getEmailVerified())) {
                        log.warn("Resend verification skipped - already verified. email={}", maskEmail(request.getEmail()));
                        return Mono.empty();
                    }

                    // STATUS BUKAN PENDING — akun mungkin suspended/deleted
                    if (user.getStatus() != UserStatus.PENDING_VERIFICATION) {
                        log.warn("Resend verification skipped - invalid status. email={}, status={}",
                                maskEmail(request.getEmail()), user.getStatus());
                        return Mono.empty();
                    }

                    // GENERATE OTP BARU + KIRIM EMAIL
                    return emailOtpService.generateAndStoreOtp(request.getEmail())
                            .flatMap(otp -> emailService.sendVerificationOtp(request.getEmail(), otp))
                            .doOnSuccess(v -> log.info("Verification OTP resent. email={}", maskEmail(request.getEmail())));
                })
                // SELALU return success — jangan expose apakah email terdaftar atau tidak
                .then()
                .doOnError(e -> log.error("Failed to resend verification OTP. email={}, reason={}",
                        maskEmail(request.getEmail()), e.getMessage()))
                .onErrorComplete();
    }

    // -------------------------------------------------------------------------
    // AUTHENTICATION
    // -------------------------------------------------------------------------

    /**
     * Authenticates a user with email and password (Step 1 of the login flow).
     *
     * <p>Flow:
     * <ol>
     *   <li>Look up the user by email</li>
     *   <li>Reject immediately if the account is still within its lock period</li>
     *   <li>Validate the password; delegate to {@link #handleFailedLogin} on mismatch</li>
     *   <li>Reject if the account status is not {@code ACTIVE}</li>
     *   <li>Reset the failed-login counter on success</li>
     *   <li>If MFA is enabled: issue a short-lived MFA token</li>
     *   <li>If MFA is disabled: issue an access token and a refresh token directly</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>{@link UserExceptions.LoginFailException} is intentionally generic —
     *       "email not found" and "wrong password" return the same error to prevent user enumeration.</li>
     *   <li>IP address and user-agent are logged for banking compliance audit trails.</li>
     *   <li>Passwords are never logged; emails are masked to protect PII.</li>
     * </ul>
     *
     * @param request   login payload (email + password)
     * @param ipAddress originating IP address for audit logging
     * @param userAgent originating user-agent for audit logging
     * @return {@link LoginResponse} containing either an MFA token or a full token pair
     */
    public Mono<LoginResponse> loginUser(LoginRequest request, String ipAddress, String userAgent) {
        return userRepository.findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // CHECK ACCOUNT LOCKED
                    if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
                        log.warn("Login failed - account locked. userCode={}, lockedUntil={}, ip={}",
                                user.getUserCode(), user.getLockedUntil(), ipAddress);
                        return Mono.error(new UserExceptions.AccountLockedException(user.getLockedUntil()));
                    }

                    // VALIDATE PASSWORD
                    if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
                        log.warn("Login failed - wrong password. email={}, ip={}",
                                maskEmail(request.getEmail()), ipAddress);
                        return handleFailedLogin(user);
                    }

                    // VALIDATE STATUS
                    if (user.getStatus() != UserStatus.ACTIVE) {
                        log.warn("Login failed - user not active. userCode={}, status={}, ip={}",
                                user.getUserCode(), user.getStatus(), ipAddress);
                        return Mono.error(new UserExceptions.UnactivatedException());
                    }

                    // RESET FAILED LOGIN COUNTER ON SUCCESS
                    return userRepository.updateFailedLoginAttempts(user.getId(), (short) 0, Instant.now())
                            .then(Mono.fromCallable(() -> {
                                if (user.getMfaEnabled()) {

                                    String mfaToken = jwtUtil.generateMfaToken(user);

                                    return LoginResponse.builder()
                                            .mfaRequired(true)
                                            .mfaToken(mfaToken)
                                            .expiresIn(jwtUtil.getMfaTokenExpirationInSeconds())
                                            .build();
                                } else {

                                    String accessToken = jwtUtil.generateAccessToken(user);
                                    String refreshToken = jwtUtil.generateRefreshToken(user);

                                    return LoginResponse.builder()
                                            .mfaRequired(false)
                                            .accessToken(accessToken)
                                            .refreshToken(refreshToken)
                                            .expiresIn(jwtUtil.getAccessTokenExpirationInSeconds())
                                            .build();
                                }
                            }))
                            .flatMap(response ->
                                    eventPublisher.publish(
                                            AuthEventType.LOGIN_SUCCESS,
                                            user.getUserCode(),
                                            maskEmail(request.getEmail()),
                                            ipAddress, userAgent, null
                                    ).thenReturn(response)
                            );
                })
                .doOnSuccess(response ->
                        log.info("Login success. MFA required={}, email={}, ip={}",
                                response.getMfaRequired(),
                                maskEmail(request.getEmail()),
                                ipAddress)
                )
                .doOnError(error ->
                        log.warn("Login failed. email={}, ip={}, reason={}",
                                maskEmail(request.getEmail()), ipAddress, error.getMessage())
                )
                .as(transactionalOperator::transactional);
    }

    /**
     * Handles a failed login attempt by incrementing the counter and locking the account
     * when the maximum number of consecutive failures is reached.
     *
     * <p>Lock policy: after {@value #MAX_FAILED_ATTEMPTS} consecutive failures the account
     * is locked for {@value #LOCK_DURATION_MINUTES} minutes.
     *
     * @param user the user entity that failed authentication
     * @return an error {@link Mono} — either {@link UserExceptions.AccountLockedException}
     * or {@link UserExceptions.LoginFailException}
     */
    private Mono<LoginResponse> handleFailedLogin(User user) {
        short newFailedCount = (short) (user.getFailedLogin() + 1);
        Instant now = Instant.now();

        if (newFailedCount >= MAX_FAILED_ATTEMPTS) {
            // LOCK ACCOUNT
            Instant lockedUntil = now.plus(LOCK_DURATION_MINUTES, ChronoUnit.MINUTES);
            log.warn("Account locked due to too many failed attempts. userCode={}, lockedUntil={}",
                    user.getUserCode(), lockedUntil);

            return userRepository.updateFailedLoginAttempts(user.getId(), newFailedCount, now)
                    .then(userRepository.lockUser(user.getId(), lockedUntil, now))
                    .then(eventPublisher.publish(
                            newFailedCount >= MAX_FAILED_ATTEMPTS
                                    ? AuthEventType.ACCOUNT_LOCKED
                                    : AuthEventType.LOGIN_FAILED,
                            user.getUserCode(),
                            maskEmail(user.getEmail()),
                            null, null,
                            Map.of("failedAttempts", newFailedCount)   // ← metadata
                    ))
                    .then(Mono.error(new UserExceptions.AccountLockedException(lockedUntil)));
        }

        // INCREMENT FAILED COUNTER
        log.warn("Failed login attempt {}/{} for userCode={}",
                newFailedCount, MAX_FAILED_ATTEMPTS, user.getUserCode());

        return userRepository.updateFailedLoginAttempts(user.getId(), newFailedCount, now)
                .then(Mono.error(new UserExceptions.LoginFailException()));
    }

    // -------------------------------------------------------------------------
    // MULTI-FACTOR AUTHENTICATION (MFA)
    // -------------------------------------------------------------------------

    /**
     * Initiates MFA setup by generating a TOTP secret and a QR code for the user.
     *
     * <p>Flow:
     * <ol>
     *   <li>Fetch the user from the database using the ID from the security context</li>
     *   <li>Ensure the email has been verified before allowing MFA setup</li>
     *   <li>Ensure MFA has not already been enabled</li>
     *   <li>Generate a TOTP secret</li>
     *   <li>Persist the secret ({@code mfaEnabled} remains {@code false} until confirmed)</li>
     *   <li>Generate a QR code as a Base64-encoded PNG on the server side</li>
     *   <li>Return the QR code and the plain-text secret for manual entry as a backup</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>The QR code is generated server-side — the secret is never sent to a third-party API.</li>
     *   <li>{@code mfaEnabled} is set to {@code true} only after the first OTP is confirmed
     *       via {@code /mfa/setup/verify}.</li>
     *   <li>Consider encrypting {@code mfaSecret} at rest (AES-256) for production.</li>
     * </ul>
     *
     * @param userId ID of the authenticated user (extracted from the JWT)
     * @return {@link MfaSetupResponse} containing the QR code and the plain-text secret
     */
    public Mono<MfaSetupResponse> setupMfa(String userId) {
        return userRepository.findById(UUID.fromString(userId))
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // PASTIKAN EMAIL SUDAH VERIFIED
                    if (!Boolean.TRUE.equals(user.getEmailVerified())) {
                        log.warn("MFA setup failed - email not verified. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.EmailNotVerifiedException());
                    }

                    // PASTIKAN MFA BELUM DI-SETUP
                    if (Boolean.TRUE.equals(user.getMfaEnabled())) {
                        log.warn("MFA setup failed - MFA already enabled. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.MfaAlreadyEnabledException());
                    }

                    // GENERATE SECRET
                    String secret = otpService.generateSecret();

                    // SIMPAN SECRET KE DB — mfa_enabled masih false sampai verify pertama
                    return userRepository.save(
                            user.toBuilder()
                                    .mfaSecret(secret)
                                    .mfaEnabled(false)
                                    .build()
                    ).flatMap((User savedUser) -> {  // ← tambah explicit type (User savedUser)
                        try {
                            String qrCode = otpService.generateQrCodeBase64(savedUser.getEmail(), secret);
                            log.debug("MFA setup QR generated. userCode={}", savedUser.getUserCode());

                            return Mono.just(MfaSetupResponse.builder()
                                    .qrCode(qrCode)
                                    .secret(secret)
                                    .build());

                        } catch (QrGenerationException e) {
                            log.error("Failed to generate QR code. userCode={}", savedUser.getUserCode());
                            return Mono.error(new RuntimeException("Failed to generate QR code"));
                        }
                    });
                })
                .doOnSuccess(response ->
                        log.info("MFA setup initiated successfully. userId={}", userId)
                )
                .as(transactionalOperator::transactional);
    }


    /**
     * Confirms the MFA setup by verifying the first TOTP code from the authenticator app.
     * Sets {@code mfaEnabled = true} upon success.
     *
     * <p>Flow:
     * <ol>
     *   <li>Fetch the user by ID</li>
     *   <li>Ensure the TOTP secret exists (setup must have been initiated first)</li>
     *   <li>Ensure MFA is not already enabled</li>
     *   <li>Verify the OTP against the stored secret</li>
     *   <li>Set {@code mfaEnabled = true}</li>
     * </ol>
     *
     * @param userId  ID of the authenticated user (extracted from the JWT)
     * @param request contains the 6-digit OTP from Google Authenticator
     * @return {@link MfaSetupVerifyResponse} confirming that MFA is now active
     */
    public Mono<MfaSetupVerifyResponse> verifyMfaSetup(String userId, MfaSetupVerifyRequest request) {
        return userRepository.findById(UUID.fromString(userId))
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // PASTIKAN SETUP SUDAH DILAKUKAN
                    if (user.getMfaSecret() == null) {
                        log.warn("MFA setup verify failed - no secret found. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.MfaNotSetupException());
                    }

                    // PASTIKAN BELUM PERNAH VERIFY
                    if (Boolean.TRUE.equals(user.getMfaEnabled())) {
                        log.warn("MFA setup verify failed - MFA already enabled. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.MfaAlreadyEnabledException());
                    }

                    // VERIFY OTP
                    boolean isValid = otpService.verifyOtp(user.getMfaSecret(), request.getOtpCode());
                    if (!isValid) {
                        log.warn("MFA setup verify failed - invalid OTP. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.InvalidOtpException());
                    }

                    // AKTIFKAN MFA
                    return userRepository.save(
                            user.toBuilder()
                                    .mfaEnabled(true)
                                    .build()
                    ).flatMap(updatedUser ->
                            eventPublisher.publish(
                                    AuthEventType.MFA_ENABLED,
                                    updatedUser.getUserCode(),
                                    maskEmail(updatedUser.getEmail()),
                                    null, null, null
                            ).thenReturn(updatedUser)
                    );
                })
                .map(updatedUser -> {
                    log.info("MFA enabled successfully. userCode={}", updatedUser.getUserCode());
                    return MfaSetupVerifyResponse.builder()
                            .mfaEnabled(true)
                            .message("MFA has been enabled. You will need Google Authenticator for future logins.")
                            .build();
                })
                .as(transactionalOperator::transactional);
    }

    /**
     * Validates the MFA OTP and issues a full token pair (access + refresh).
     * This is Step 2 of the login flow for MFA-enabled accounts.
     *
     * <p>Flow:
     * <ol>
     *   <li>Fetch the user from the database by ID (injected into the security context by the JWT filter)</li>
     *   <li>Ensure MFA is enabled and a secret exists</li>
     *   <li>Verify the OTP against the stored TOTP secret</li>
     *   <li>Generate an access token and a refresh token</li>
     *   <li>Hash the refresh token (SHA-256) and persist it with IP and user-agent metadata</li>
     *   <li>Update {@code lastLoginAt}</li>
     *   <li>Return both tokens</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>The MFA token in the {@code Authorization} header has already been validated
     *       by {@code JwtAuthenticationFilter} before this method is called.</li>
     *   <li>Refresh tokens are stored as SHA-256 hashes — plain tokens never touch the database.</li>
     *   <li>Generic error messages are used on OTP failure to avoid information leakage.</li>
     *   <li>IP address and user-agent are persisted for banking compliance audit trails.</li>
     * </ul>
     *
     * @param userId    ID of the authenticated user (extracted from the MFA JWT)
     * @param request   contains the 6-digit OTP from Google Authenticator
     * @param ipAddress originating IP address for audit logging
     * @param userAgent originating user-agent for audit logging
     * @return {@link MfaValidateResponse} containing the access token, refresh token, and user metadata
     */
    public Mono<MfaValidateResponse> validateMfa(String userId, MfaValidateRequest request,
                                                 String ipAddress, String userAgent) {
        return userRepository.findById(UUID.fromString(userId))
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // PASTIKAN MFA SUDAH ENABLED
                    if (!Boolean.TRUE.equals(user.getMfaEnabled())) {
                        log.warn("MFA validate failed - MFA not enabled. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.MfaNotSetupException());
                    }

                    // PASTIKAN SECRET ADA
                    if (user.getMfaSecret() == null) {
                        log.warn("MFA validate failed - no secret found. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.MfaNotSetupException());
                    }

                    // VERIFY OTP
                    boolean isValid = otpService.verifyOtp(user.getMfaSecret(), request.getOtpCode());
                    if (!isValid) {
                        log.warn("MFA validate failed - invalid OTP. userCode={}, ip={}", user.getUserCode(), ipAddress);
                        return Mono.error(new UserExceptions.InvalidOtpException());
                    }

                    // GENERATE TOKENS
                    String accessToken = jwtUtil.generateAccessToken(user);
                    String refreshToken = jwtUtil.generateRefreshToken(user);
                    String refreshTokenHash = hashToken(refreshToken);

                    // BUILD REFRESH TOKEN ENTITY
                    RefreshToken refreshTokenEntity = RefreshToken.builder()
                            .userId(user.getId())
                            .tokenHash(refreshTokenHash)
                            .expiresAt(Instant.now().plusSeconds(jwtUtil.getRefreshTokenExpirationInSeconds()))
                            .revoked(false)
                            .ipAddress(ipAddress)
                            .userAgent(userAgent)
                            .build();

                    // SIMPAN REFRESH TOKEN + UPDATE LAST LOGIN
                    return refreshTokenRepository.save(refreshTokenEntity)
                            .then(userRepository.updateSuccessfulLogin(user.getId(), Instant.now()))
                            .then(eventPublisher.publish(
                                    AuthEventType.MFA_VALIDATED,
                                    user.getUserCode(),
                                    maskEmail(user.getEmail()),
                                    ipAddress, userAgent, null
                            ))
                            .thenReturn(MfaValidateResponse.builder()
                                    .accessToken(accessToken)
                                    .refreshToken(refreshToken)
                                    .tokenType("Bearer")
                                    .expiresIn(jwtUtil.getAccessTokenExpirationInSeconds())
                                    .userCode(user.getUserCode())
                                    .role(user.getRole().name())
                                    .build());
                })
                .doOnSuccess(response ->
                        log.info("MFA validated successfully - tokens issued. userCode={}, ip={}, userAgent={}",
                                response.getUserCode(), ipAddress, userAgent)
                )
                .doOnError(error ->
                        log.warn("MFA validate failed. userId={}, ip={}, reason={}",
                                userId, ipAddress, error.getMessage())
                )
                .as(transactionalOperator::transactional);
    }


    // -------------------------------------------------------------------------
    // TOKEN MANAGEMENT
    // -------------------------------------------------------------------------

    /**
     * Revokes a refresh token, effectively logging the user out of the current session.
     *
     * <p>Flow:
     * <ol>
     *   <li>Hash the supplied refresh token</li>
     *   <li>Look up the token in the database by its hash</li>
     *   <li>Verify the token is still valid (not expired, not already revoked)</li>
     *   <li>Verify the token belongs to the currently authenticated user</li>
     *   <li>Mark the token as revoked</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>Plain refresh tokens are never stored in the database — only their SHA-256 hash.</li>
     *   <li>Revoked tokens cannot be reused.</li>
     *   <li>This endpoint requires a valid access token in the {@code Authorization} header.</li>
     * </ul>
     *
     * @param userId  ID of the authenticated user (extracted from the JWT)
     * @param request contains the refresh token to revoke
     * @return empty {@link Mono} on success
     */
    public Mono<Void> logout(String userId, LogoutRequest request) {
        String tokenHash = hashToken(request.getRefreshToken());

        return refreshTokenRepository.findValidTokenByHash(tokenHash, Instant.now())
                .switchIfEmpty(Mono.error(new UserExceptions.InvalidRefreshTokenException()))
                .flatMap(refreshToken -> {

                    // PASTIKAN TOKEN MILIK USER YANG SEDANG LOGIN
                    if (!refreshToken.getUserId().toString().equals(userId)) {
                        log.warn("Logout failed - token does not belong to user. userId={}", userId);
                        return Mono.error(new UserExceptions.InvalidRefreshTokenException());
                    }

                    return refreshTokenRepository.revokeToken(tokenHash, Instant.now());
                })
                .doOnSuccess(v -> log.info("Logout successful. userId={}", userId))
                .doOnError(e -> log.warn("Logout failed. userId={}, reason={}", userId, e.getMessage()))
                .as(transactionalOperator::transactional);
    }

    /**
     * Exchanges a valid refresh token for a new access token.
     *
     * <p>Flow:
     * <ol>
     *   <li>The refresh token in the {@code Authorization} header has already been validated
     *       (signature, expiry, type = "refresh") by {@code JwtAuthenticationFilter}</li>
     *   <li>The user ID has already been injected into the security context by the filter</li>
     *   <li>Hash the token and look it up in the database</li>
     *   <li>Verify it has not been revoked and belongs to the requesting user</li>
     *   <li>Verify the user account is still {@code ACTIVE}</li>
     *   <li>Issue a new access token</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>The token is taken from the {@code Authorization} header, not the request body.</li>
     *   <li>The JWT filter handles cryptographic validation; this method only checks revocation status.</li>
     *   <li>Refresh token rotation can be added here in a future iteration.</li>
     * </ul>
     *
     * @param userId          ID of the authenticated user (extracted from the refresh JWT)
     * @param rawRefreshToken the plain refresh token from the {@code Authorization} header
     * @return {@link RefreshTokenResponse} containing the new access token
     */
    public Mono<RefreshTokenResponse> refreshToken(String userId, String rawRefreshToken) {
        String tokenHash = hashToken(rawRefreshToken);

        return refreshTokenRepository.findValidTokenByHash(tokenHash, Instant.now())
                .switchIfEmpty(Mono.error(new UserExceptions.InvalidRefreshTokenException()))
                .flatMap(refreshToken -> {

                    // PASTIKAN TOKEN MILIK USER YANG SEDANG LOGIN
                    if (!refreshToken.getUserId().toString().equals(userId)) {
                        log.warn("Refresh failed - token does not belong to user. userId={}", userId);
                        return Mono.error(new UserExceptions.InvalidRefreshTokenException());
                    }

                    return userRepository.findById(refreshToken.getUserId());
                })
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // PASTIKAN USER MASIH ACTIVE
                    if (user.getStatus() != UserStatus.ACTIVE) {
                        log.warn("Refresh failed - user not active. userCode={}, status={}",
                                user.getUserCode(), user.getStatus());
                        return Mono.error(new UserExceptions.LoginFailException());
                    }

                    String newAccessToken = jwtUtil.generateAccessToken(user);
                    log.info("Token refreshed successfully. userCode={}", user.getUserCode());

                    return Mono.just(RefreshTokenResponse.builder()
                            .accessToken(newAccessToken)
                            .tokenType("Bearer")
                            .expiresIn(jwtUtil.getAccessTokenExpirationInSeconds())
                            .build());
                })
                .doOnError(error ->
                        log.warn("Token refresh failed. userId={}, reason={}", userId, error.getMessage())
                )
                .as(transactionalOperator::transactional);
    }


    // -------------------------------------------------------------------------
    // PASSWORD MANAGEMENT
    // -------------------------------------------------------------------------

    /**
     * Changes the password of the currently authenticated user.
     *
     * <p>Flow:
     * <ol>
     *   <li>Fetch the user from the database by ID</li>
     *   <li>Verify the current password</li>
     *   <li>Reject if the new password is the same as the current password</li>
     *   <li>Reject if the confirmation password does not match the new password</li>
     *   <li>Hash and persist the new password</li>
     *   <li>Revoke all active refresh tokens to force re-login on all devices</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>Revoking all refresh tokens on password change is standard banking practice.</li>
     *   <li>The current password must be verified before any change is applied.</li>
     * </ul>
     *
     * @param userId  ID of the authenticated user (extracted from the JWT)
     * @param request contains the current password, new password, and confirmation
     * @return empty {@link Mono} on success
     */
    public Mono<Void> changePassword(String userId, ChangePasswordRequest request) {
        return userRepository.findById(UUID.fromString(userId))
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // VERIFY CURRENT PASSWORD
                    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
                        log.warn("Change password failed - wrong current password. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.InvalidCurrentPasswordException());
                    }

                    // PASTIKAN NEW PASSWORD BERBEDA
                    if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
                        log.warn("Change password failed - new password same as current. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.SamePasswordException());
                    }

                    // PASTIKAN CONFIRM PASSWORD MATCH
                    if (!request.getNewPassword().equals(request.getConfirmPassword())) {
                        log.warn("Change password failed - confirm password mismatch. userCode={}", user.getUserCode());
                        return Mono.error(new UserExceptions.PasswordMismatchException());
                    }

                    String newPasswordHash = passwordEncoder.encode(request.getNewPassword());

                    // UPDATE PASSWORD + REVOKE SEMUA REFRESH TOKEN
                    return userRepository.updatePassword(user.getId(), newPasswordHash, Instant.now())
                            .then(refreshTokenRepository.revokeAllUserTokens(user.getId(), Instant.now()))
                            .then(eventPublisher.publish(
                                    AuthEventType.PASSWORD_CHANGED,
                                    user.getUserCode(),
                                    maskEmail(user.getEmail()),
                                    null, null, null
                            ))
                            .doOnSuccess(v -> log.info("Password changed successfully. userCode={}", user.getUserCode()));
                })
                .as(transactionalOperator::transactional);
    }

    /**
     * Sends a password-reset OTP to the given email address.
     *
     * <p>Flow:
     * <ol>
     *   <li>Look up the user by email</li>
     *   <li>Generate a reset OTP and store it in Redis under the {@code reset-otp:<email>} key (TTL: 3 minutes)</li>
     *   <li>Send the OTP via email</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>Always returns success regardless of whether the email is registered (prevents user enumeration).</li>
     *   <li>The reset OTP TTL (3 minutes) is shorter than the registration OTP TTL (5 minutes).</li>
     *   <li>This endpoint is public — no authentication token required.</li>
     * </ul>
     *
     * @param request contains the email address to send the reset OTP to
     * @return empty {@link Mono} on completion
     */
    public Mono<Void> forgotPassword(ForgotPasswordRequest request) {
        return userRepository.findByEmail(request.getEmail())
                .flatMap(user ->
                        emailOtpService.generateAndStoreResetOtp(request.getEmail())
                                .flatMap(otp -> emailService.sendResetPasswordOtp(request.getEmail(), otp))
                                .doOnSuccess(v -> log.info("Reset password OTP sent. email={}", maskEmail(request.getEmail())))
                )
                // SELALU return success — jangan expose apakah email terdaftar atau tidak
                .then()
                .doOnError(e -> log.error("Failed to send reset OTP. email={}, reason={}",
                        maskEmail(request.getEmail()), e.getMessage()))
                .onErrorComplete(); // swallow error — tetap return 200
    }

    /**
     * Resets the user's password using the OTP received via email.
     *
     * <p>Flow:
     * <ol>
     *   <li>Verify the OTP from Redis (single-use — deleted immediately after verification)</li>
     *   <li>Fetch the user by email</li>
     *   <li>Reject if the confirmation password does not match the new password</li>
     *   <li>Reject if the new password is the same as the current password</li>
     *   <li>Hash and persist the new password</li>
     *   <li>Revoke all active refresh tokens to force re-login on all devices</li>
     * </ol>
     *
     * <p>Security notes:
     * <ul>
     *   <li>The OTP is deleted from Redis immediately after the verification attempt.</li>
     *   <li>All refresh tokens are revoked after a successful reset.</li>
     * </ul>
     *
     * @param request contains the email, the 6-digit OTP, the new password, and confirmation
     * @return empty {@link Mono} on success
     */
    public Mono<Void> resetPassword(ResetPasswordRequest request) {
        return emailOtpService.verifyResetOtp(request.getEmail(), request.getOtpCode())
                .flatMap(isValid -> {
                    if (!isValid) {
                        log.warn("Reset password failed - invalid or expired OTP. email={}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.InvalidOtpException());
                    }
                    return userRepository.findByEmail(request.getEmail());
                })
                .switchIfEmpty(Mono.error(new UserExceptions.LoginFailException()))
                .flatMap(user -> {

                    // PASTIKAN CONFIRM PASSWORD MATCH
                    if (!request.getNewPassword().equals(request.getConfirmPassword())) {
                        log.warn("Reset password failed - confirm password mismatch. email={}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.PasswordMismatchException());
                    }

                    // PASTIKAN NEW PASSWORD BERBEDA DARI CURRENT
                    if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
                        log.warn("Reset password failed - new password same as current. email={}", maskEmail(request.getEmail()));
                        return Mono.error(new UserExceptions.SamePasswordException());
                    }

                    String newPasswordHash = passwordEncoder.encode(request.getNewPassword());

                    // UPDATE PASSWORD + REVOKE SEMUA REFRESH TOKEN
                    return userRepository.updatePassword(user.getId(), newPasswordHash, Instant.now())
                            .then(refreshTokenRepository.revokeAllUserTokens(user.getId(), Instant.now()))
                            .then(eventPublisher.publish(
                                    AuthEventType.PASSWORD_RESET,
                                    user.getUserCode(),
                                    maskEmail(user.getEmail()),
                                    null, null, null
                            ))
                            .doOnSuccess(v -> log.info("Password reset successfully. userCode={}", user.getUserCode()));
                })
                .as(transactionalOperator::transactional);
    }


    // -------------------------------------------------------------------------
    // PRIVATE HELPERS
    // -------------------------------------------------------------------------

    /**
     * Masks an email address for safe inclusion in logs (PII protection).
     *
     * <p>Example: {@code koriebruh@gmail.com} → {@code k*******h@gmail.com}
     *
     * @param email the raw email address
     * @return the masked email string
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        String local = parts[0];
        if (local.length() <= 2) return "**@" + parts[1];
        return local.charAt(0) + "*".repeat(local.length() - 2) + local.charAt(local.length() - 1) + "@" + parts[1];
    }


    /**
     * Computes the SHA-256 hash of the given token and returns it as a Base64-encoded string.
     * Used to store and compare refresh tokens without persisting the plain-text value.
     *
     * @param token the plain-text token to hash
     * @return Base64-encoded SHA-256 hash
     * @throws RuntimeException if the SHA-256 algorithm is unavailable (should never happen on a standard JVM)
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }

}
