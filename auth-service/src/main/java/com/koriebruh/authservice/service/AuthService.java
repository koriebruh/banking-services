package com.koriebruh.authservice.service;

import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.mapper.UserMapper;
import com.koriebruh.authservice.dto.request.*;
import com.koriebruh.authservice.dto.response.LoginResponse;
import com.koriebruh.authservice.dto.response.RegisterResponse;
import com.koriebruh.authservice.dto.response.VerifyEmailOtpResponse;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.exception.UserExceptions;
import com.koriebruh.authservice.repository.RefreshTokenRepository;
import com.koriebruh.authservice.repository.UserRepository;
import com.koriebruh.authservice.util.JwtUtil;
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

    private static final short MAX_FAILED_ATTEMPTS = 5;

    private static final long LOCK_DURATION_MINUTES = 15;

    /**
     * Register new user using fully reactive flow (WebFlux + R2DBC).
     * <p>
     * Flow:
     * 1. Validate unique fields asynchronously (parallel DB checks)
     * 2. Generate business userCode from database sequence
     * 3. Build entity & hash password
     * 4. Persist user inside reactive transaction
     * 5. Map to response DTO
     * <p>
     * NOTE:
     * - No blocking calls allowed.
     * - Unique constraint MUST still exist at DB level.
     * - Sequence gaps are acceptable (normal DB behavior).
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
                                .thenReturn(response)
                )
                .as(transactionalOperator::transactional);
    }

    /**
     * [SECURITY] Masking email untuk keperluan logging.
     * Contoh: koriebruh@gmail.com → k*******h@gmail.com
     * Wajib untuk compliance perbankan (PII protection).
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        String local = parts[0];
        if (local.length() <= 2) return "**@" + parts[1];
        return local.charAt(0) + "*".repeat(local.length() - 2) + local.charAt(local.length() - 1) + "@" + parts[1];
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


    /**
     * VERIFY EMAIL - Aktivasi akun setelah register.
     * <p>
     * Flow:
     * 1. Cek OTP di Redis — expired/tidak ada = error
     * 2. Verify OTP valid
     * 3. Update status user → ACTIVE, emailVerified = true
     * <p>
     * Security notes:
     * - OTP single-use, langsung dihapus dari Redis setelah dicek
     * - OTP expired otomatis setelah 5 menit (Redis TTL)
     * - Generic error untuk OTP invalid (tidak expose detail)
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


    ////api/auth/mfa/setup → scan QR Google Authenticator
    //    public Mono<> mfaSetup() {
    //
    //    }

//POST /api/auth/mfa/setup/verify → konfirmasi OTP TOTP pertama
//    public  Mono<> mfaVerify() {
//
//    }


    /**
     * LOGIN - Step 1: Credential Validation & MFA Token Issuance
     * <p>
     * Flow:
     * 1. Lookup user by email — generic error if not found (prevent user enumeration)
     * 2. Check account lock status — reject immediately if still within lock period
     * 3. Validate password — delegate to handleFailedLogin() if wrong
     * 4. Check user status — only ACTIVE users may proceed
     * 5. Reset failed login counter on success
     * 6. Generate short-lived MFA token — actual JWT issued after MFA verification
     * <p>
     * Security notes:
     * - LoginFailException is intentionally generic (email not found = wrong password = same error)
     * - IP address and userAgent are logged for audit trail (banking compliance)
     * - Password is never logged, email is masked in logs (PII protection)
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
                                String mfaToken = jwtUtil.generateMfaToken(user);
                                return LoginResponse.builder()
                                        .mfaRequired(true)
                                        .mfaToken(mfaToken)
                                        .expiresIn(jwtUtil.getMfaTokenExpirationInSeconds())
                                        .build();
                            }));
                })
                .doOnSuccess(response ->
                        log.info("Login step 1 success - MFA token issued. email={}, ip={}, userAgent={}",
                                maskEmail(request.getEmail()), ipAddress, userAgent)
                )
                .doOnError(error ->
                        log.warn("Login failed. email={}, ip={}, reason={}",
                                maskEmail(request.getEmail()), ipAddress, error.getMessage())
                )
                .as(transactionalOperator::transactional);
    }


    /**
     * Handles failed login attempt by incrementing the failed counter.
     * <p>
     * If failed attempts reach MAX_FAILED_ATTEMPTS (5):
     * - Account is locked for LOCK_DURATION_MINUTES (15 minutes)
     * - AccountLockedException is thrown
     * <p>
     * Otherwise:
     * - Failed counter is incremented
     * - LoginFailException is thrown (generic, no detail exposed to client)
     * <p>
     * Note:
     * - Counter is reset to 0 on successful login (see loginUser above)
     * - Database unique constraints remain the last line of defense against race conditions
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
                    .then(Mono.error(new UserExceptions.AccountLockedException(lockedUntil)));
        }

        // INCREMENT FAILED COUNTER
        log.warn("Failed login attempt {}/{} for userCode={}",
                newFailedCount, MAX_FAILED_ATTEMPTS, user.getUserCode());

        return userRepository.updateFailedLoginAttempts(user.getId(), newFailedCount, now)
                .then(Mono.error(new UserExceptions.LoginFailException()));
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }


    // MFA VERIFICATION, ini dapet token
//    public Mono<MfaVerifyResponse> verifyMfa(MfaVerifyRequest request) {
//        // verif mfa
//        // generate access token, refresh token
//        // simpan refresh token ke db (hash)
//        // return access token, refresh token\
//
//        jwtUtil.getMfaTokenExpirationInSeconds()
//
//
//    }

    // LOGOUT
//    public Mono<LogoutRequest> logoutRequest (LoginRequest request) {
//
//    }


//    // REFRESH TOKEN
//    public Mono<> refreshToken(){}


}
