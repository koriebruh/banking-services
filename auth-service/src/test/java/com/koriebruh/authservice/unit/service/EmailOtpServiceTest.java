package com.koriebruh.authservice.unit.service;

import com.koriebruh.authservice.service.EmailOtpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("EmailOtpService Unit Tests")
class EmailOtpServiceTest {

    @Mock
    private ReactiveStringRedisTemplate redisTemplate;

    @Mock
    private ReactiveValueOperations<String, String> valueOperations;

    private EmailOtpService emailOtpService;

    private static final String TEST_EMAIL = "test@example.com";

    @BeforeEach
    void setUp() {
        emailOtpService = new EmailOtpService(redisTemplate);
    }

    @Nested
    @DisplayName("Generate And Store OTP")
    class GenerateAndStoreOtp {

        @Test
        @DisplayName("Should generate 6-digit OTP and store in Redis")
        void shouldGenerateAndStoreOtp() {
            // Given
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));

            // When
            StepVerifier.create(emailOtpService.generateAndStoreOtp(TEST_EMAIL))
                    .assertNext(otp -> {
                        assertThat(otp).isNotNull();
                        assertThat(otp).hasSize(6);
                        assertThat(otp).matches("\\d{6}");
                    })
                    .verifyComplete();

            // Then
            verify(valueOperations).set(eq("email-otp:" + TEST_EMAIL), anyString(), eq(Duration.ofMinutes(5)));
        }

        @Test
        @DisplayName("Should use correct Redis key format")
        void shouldUseCorrectRedisKeyFormat() {
            // Given
            ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.set(keyCaptor.capture(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));

            // When
            StepVerifier.create(emailOtpService.generateAndStoreOtp(TEST_EMAIL))
                    .expectNextCount(1)
                    .verifyComplete();

            // Then
            assertThat(keyCaptor.getValue()).isEqualTo("email-otp:" + TEST_EMAIL);
        }

        @Test
        @DisplayName("Should set 5 minute expiry for OTP")
        void shouldSetCorrectExpiryForOtp() {
            // Given
            ArgumentCaptor<Duration> durationCaptor = ArgumentCaptor.forClass(Duration.class);
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.set(anyString(), anyString(), durationCaptor.capture()))
                    .thenReturn(Mono.just(true));

            // When
            StepVerifier.create(emailOtpService.generateAndStoreOtp(TEST_EMAIL))
                    .expectNextCount(1)
                    .verifyComplete();

            // Then
            assertThat(durationCaptor.getValue()).isEqualTo(Duration.ofMinutes(5));
        }
    }

    @Nested
    @DisplayName("Verify OTP")
    class VerifyOtp {

        @Test
        @DisplayName("Should return true for valid OTP")
        void shouldReturnTrueForValidOtp() {
            // Given
            String validOtp = "123456";
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("email-otp:" + TEST_EMAIL)).thenReturn(Mono.just(validOtp));
            when(redisTemplate.delete("email-otp:" + TEST_EMAIL)).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(emailOtpService.verifyOtp(TEST_EMAIL, validOtp))
                    .expectNext(true)
                    .verifyComplete();

            // Verify OTP is deleted after verification (single-use)
            verify(redisTemplate).delete("email-otp:" + TEST_EMAIL);
        }

        @Test
        @DisplayName("Should return false for invalid OTP")
        void shouldReturnFalseForInvalidOtp() {
            // Given
            String storedOtp = "123456";
            String wrongOtp = "654321";
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("email-otp:" + TEST_EMAIL)).thenReturn(Mono.just(storedOtp));
            when(redisTemplate.delete("email-otp:" + TEST_EMAIL)).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(emailOtpService.verifyOtp(TEST_EMAIL, wrongOtp))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should return false for expired OTP (key not found)")
        void shouldReturnFalseForExpiredOtp() {
            // Given
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("email-otp:" + TEST_EMAIL)).thenReturn(Mono.empty());

            // When/Then
            StepVerifier.create(emailOtpService.verifyOtp(TEST_EMAIL, "123456"))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should delete OTP after verification attempt")
        void shouldDeleteOtpAfterVerification() {
            // Given
            String storedOtp = "123456";
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("email-otp:" + TEST_EMAIL)).thenReturn(Mono.just(storedOtp));
            when(redisTemplate.delete("email-otp:" + TEST_EMAIL)).thenReturn(Mono.just(1L));

            // When
            StepVerifier.create(emailOtpService.verifyOtp(TEST_EMAIL, storedOtp))
                    .expectNext(true)
                    .verifyComplete();

            // Then
            verify(redisTemplate).delete("email-otp:" + TEST_EMAIL);
        }
    }

    @Nested
    @DisplayName("Generate And Store Reset OTP")
    class GenerateAndStoreResetOtp {

        @Test
        @DisplayName("Should generate and store reset OTP with 3 minute expiry")
        void shouldGenerateAndStoreResetOtp() {
            // Given
            ArgumentCaptor<Duration> durationCaptor = ArgumentCaptor.forClass(Duration.class);
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.set(anyString(), anyString(), durationCaptor.capture()))
                    .thenReturn(Mono.just(true));

            // When
            StepVerifier.create(emailOtpService.generateAndStoreResetOtp(TEST_EMAIL))
                    .assertNext(otp -> {
                        assertThat(otp).hasSize(6);
                        assertThat(otp).matches("\\d{6}");
                    })
                    .verifyComplete();

            // Then
            assertThat(durationCaptor.getValue()).isEqualTo(Duration.ofMinutes(3));
        }

        @Test
        @DisplayName("Should use reset-otp prefix for key")
        void shouldUseResetOtpPrefix() {
            // Given
            ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.set(keyCaptor.capture(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));

            // When
            StepVerifier.create(emailOtpService.generateAndStoreResetOtp(TEST_EMAIL))
                    .expectNextCount(1)
                    .verifyComplete();

            // Then
            assertThat(keyCaptor.getValue()).isEqualTo("reset-otp:" + TEST_EMAIL);
        }
    }

    @Nested
    @DisplayName("Verify Reset OTP")
    class VerifyResetOtp {

        @Test
        @DisplayName("Should return true for valid reset OTP")
        void shouldReturnTrueForValidResetOtp() {
            // Given
            String validOtp = "123456";
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("reset-otp:" + TEST_EMAIL)).thenReturn(Mono.just(validOtp));
            when(redisTemplate.delete("reset-otp:" + TEST_EMAIL)).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(emailOtpService.verifyResetOtp(TEST_EMAIL, validOtp))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should return false for invalid reset OTP")
        void shouldReturnFalseForInvalidResetOtp() {
            // Given
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("reset-otp:" + TEST_EMAIL)).thenReturn(Mono.just("123456"));
            when(redisTemplate.delete("reset-otp:" + TEST_EMAIL)).thenReturn(Mono.just(1L));

            // When/Then
            StepVerifier.create(emailOtpService.verifyResetOtp(TEST_EMAIL, "654321"))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should return false for expired reset OTP")
        void shouldReturnFalseForExpiredResetOtp() {
            // Given
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("reset-otp:" + TEST_EMAIL)).thenReturn(Mono.empty());

            // When/Then
            StepVerifier.create(emailOtpService.verifyResetOtp(TEST_EMAIL, "123456"))
                    .expectNext(false)
                    .verifyComplete();
        }
    }
}

