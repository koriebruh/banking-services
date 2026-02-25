package com.koriebruh.authservice.service;

import com.koriebruh.authservice.dto.mapper.UserMapper;
import com.koriebruh.authservice.dto.request.RegisterRequest;
import com.koriebruh.authservice.dto.response.RegisterResponse;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.exception.UserExceptions;
import com.koriebruh.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final PasswordEncoder passwordEncoder;

    private final TransactionalOperator transactionalOperator;

    /**
     * Register new user using fully reactive flow (WebFlux + R2DBC).
     *
     * Flow:
     * 1. Validate unique fields asynchronously (parallel DB checks)
     * 2. Generate business userCode from database sequence
     * 3. Build entity & hash password
     * 4. Persist user inside reactive transaction
     * 5. Map to response DTO
     *
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
                /*
                 * Ensure whole pipeline runs inside reactive transaction.
                 * Required for consistency if multiple DB operations involved.
                 */
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
     *
     * This method runs existence checks in parallel using Mono.zip
     * to reduce total latency.
     *
     * IMPORTANT:
     * - This is pre-validation for better user experience.
     * - Database unique constraints remain the ultimate protection
     *   against race conditions.
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


}
