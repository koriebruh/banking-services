package com.koriebruh.authservice.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.security.SecureRandom;
import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailOtpService {

    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_EXPIRY = Duration.ofMinutes(5);
    private static final String OTP_PREFIX = "email-otp:";
    private static final String RESET_OTP_PREFIX = "reset-otp:";

    private final ReactiveStringRedisTemplate redisTemplate;

    /**
     * Generate 6 digit OTP dan save to Redis with expiry 5 minute.
     * Key format: "email-otp:<email>"
     *
     * @param email email user
     * @return generated OTP string
     */
    public Mono<String> generateAndStoreOtp(String email) {
        String otp = generateOtp();
        String key = OTP_PREFIX + email;

        return redisTemplate.opsForValue()
                .set(key, otp, OTP_EXPIRY)
                .doOnSuccess(result -> log.debug("OTP stored in Redis. email={}, expiry={}m", email, OTP_EXPIRY.toMinutes()))
                .thenReturn(otp);
    }

    /**
     * Verify OTP yang diinput user terhadap yang tersimpan di Redis.
     * OTP langsung dihapus setelah dicek (single-use).
     *
     * @param email   email user
     * @param otpCode OTP yang diinput user
     * @return true jika valid
     */
    public Mono<Boolean> verifyOtp(String email, String otpCode) {
        String key = OTP_PREFIX + email;

        return redisTemplate.opsForValue()
                .get(key)
                .flatMap(storedOtp -> {
                    // Hapus OTP dari Redis setelah dicek — single use
                    log.debug("Stored OTP={}, Input OTP={}", storedOtp, otpCode);
                    return redisTemplate.delete(key)
                            .thenReturn(storedOtp.equals(otpCode));
                })
                .defaultIfEmpty(false); // key tidak ada = expired atau belum generate
    }

    /**
     * Generate random 6 digit OTP menggunakan SecureRandom.
     * SecureRandom lebih aman dari Random untuk keperluan security.
     */
    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000); // range 100000 - 999999
        return String.valueOf(otp);
    }


    /**
     * Generate OTP untuk reset password dan simpan ke Redis.
     * Key format: "reset-otp:<email>"
     * Expiry lebih pendek dari email OTP — 3 menit untuk security.
     */
    public Mono<String> generateAndStoreResetOtp(String email) {
        String otp = generateOtp();
        String key = RESET_OTP_PREFIX + email;

        return redisTemplate.opsForValue()
                .set(key, otp, Duration.ofMinutes(3)) // ← 3 menit, lebih pendek untuk security
                .doOnSuccess(result -> log.debug("Reset OTP stored in Redis. email={}", email))
                .thenReturn(otp);
    }

    /**
     * Verify reset password OTP.
     * Single-use — langsung dihapus setelah dicek.
     */
    public Mono<Boolean> verifyResetOtp(String email, String otpCode) {
        String key = RESET_OTP_PREFIX + email;

        return redisTemplate.opsForValue()
                .get(key)
                .flatMap(storedOtp -> redisTemplate.delete(key)
                        .thenReturn(storedOtp.equals(otpCode)))
                .defaultIfEmpty(false);
    }

}
