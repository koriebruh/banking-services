package com.koriebruh.authservice.unit.service;

import com.koriebruh.authservice.service.OtpService;
import dev.samstevens.totp.exceptions.QrGenerationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("OtpService Unit Tests")
class OtpServiceTest {

    private OtpService otpService;

    @BeforeEach
    void setUp() {
        otpService = new OtpService();
        ReflectionTestUtils.setField(otpService, "ISSUER", "auth-service");
    }

    @Nested
    @DisplayName("Secret Generation")
    class SecretGeneration {

        @Test
        @DisplayName("Should generate non-empty secret")
        void shouldGenerateNonEmptySecret() {
            // When
            String secret = otpService.generateSecret();

            // Then
            assertThat(secret).isNotNull().isNotBlank();
        }

        @Test
        @DisplayName("Should generate unique secrets")
        void shouldGenerateUniqueSecrets() {
            // When
            String secret1 = otpService.generateSecret();
            String secret2 = otpService.generateSecret();

            // Then
            assertThat(secret1).isNotEqualTo(secret2);
        }

        @Test
        @DisplayName("Should generate secret with valid base32 characters")
        void shouldGenerateSecretWithValidBase32Characters() {
            // When
            String secret = otpService.generateSecret();

            // Then - Base32 valid characters
            assertThat(secret).matches("[A-Z2-7]+");
        }
    }

    @Nested
    @DisplayName("QR Code Generation")
    class QrCodeGeneration {

        @Test
        @DisplayName("Should generate base64 encoded QR code")
        void shouldGenerateBase64EncodedQrCode() throws QrGenerationException {
            // Given
            String email = "test@example.com";
            String secret = otpService.generateSecret();

            // When
            String qrCode = otpService.generateQrCodeBase64(email, secret);

            // Then
            assertThat(qrCode).isNotNull().isNotBlank();
            // Verify it's valid base64 - decode should not throw
            byte[] decoded = java.util.Base64.getDecoder().decode(qrCode);
            assertThat(decoded).isNotEmpty();
        }

        @Test
        @DisplayName("Should generate different QR codes for different secrets")
        void shouldGenerateDifferentQrCodesForDifferentSecrets() throws QrGenerationException {
            // Given
            String email = "test@example.com";
            String secret1 = otpService.generateSecret();
            String secret2 = otpService.generateSecret();

            // When
            String qrCode1 = otpService.generateQrCodeBase64(email, secret1);
            String qrCode2 = otpService.generateQrCodeBase64(email, secret2);

            // Then
            assertThat(qrCode1).isNotEqualTo(qrCode2);
        }

        @Test
        @DisplayName("Should generate different QR codes for different emails")
        void shouldGenerateDifferentQrCodesForDifferentEmails() throws QrGenerationException {
            // Given
            String secret = otpService.generateSecret();

            // When
            String qrCode1 = otpService.generateQrCodeBase64("user1@example.com", secret);
            String qrCode2 = otpService.generateQrCodeBase64("user2@example.com", secret);

            // Then
            assertThat(qrCode1).isNotEqualTo(qrCode2);
        }
    }

    @Nested
    @DisplayName("OTP Verification")
    class OtpVerification {

        @Test
        @DisplayName("Should return false for invalid OTP code")
        void shouldReturnFalseForInvalidOtp() {
            // Given
            String secret = otpService.generateSecret();
            String invalidOtp = "000000";

            // When
            boolean result = otpService.verifyOtp(secret, invalidOtp);

            // Then - It's likely to be false (unless by coincidence it matches)
            // This is a probabilistic test, but 000000 is almost never valid
            // In production, we'd mock the time provider
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false for malformed OTP code")
        void shouldReturnFalseForMalformedOtp() {
            // Given
            String secret = otpService.generateSecret();

            // When
            boolean result = otpService.verifyOtp(secret, "abcdef");

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false for empty OTP code")
        void shouldReturnFalseForEmptyOtp() {
            // Given
            String secret = otpService.generateSecret();

            // When
            boolean result = otpService.verifyOtp(secret, "");

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false for null secret")
        void shouldReturnFalseForNullSecret() {
            // When/Then - This might throw or return false
            // Testing defensive behavior
            boolean result = otpService.verifyOtp(null, "123456");
            assertThat(result).isFalse();
        }
    }
}


