package com.koriebruh.authservice.unit.service;

import com.koriebruh.authservice.service.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("EmailService Unit Tests")
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    private EmailService emailService;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_OTP = "123456";

    @BeforeEach
    void setUp() {
        emailService = new EmailService(mailSender);
    }

    @Nested
    @DisplayName("Send Verification OTP")
    class SendVerificationOtp {

        @Test
        @DisplayName("Should send verification email with correct details")
        void shouldSendVerificationEmail() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendVerificationOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getTo()).containsExactly(TEST_EMAIL);
            assertThat(sentMessage.getFrom()).isEqualTo("noreply@bankingapp.com");
            assertThat(sentMessage.getSubject()).isEqualTo("Email Verification - Banking App");
            assertThat(sentMessage.getText()).contains(TEST_OTP);
            assertThat(sentMessage.getText()).contains("5 minutes");
        }

        @Test
        @DisplayName("Should include OTP in email body")
        void shouldIncludeOtpInEmailBody() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendVerificationOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getText()).contains(TEST_OTP);
        }

        @Test
        @DisplayName("Should handle mail sender exception")
        void shouldHandleMailSenderException() {
            // Given
            doThrow(new RuntimeException("SMTP connection failed"))
                    .when(mailSender).send(any(SimpleMailMessage.class));

            // When/Then
            StepVerifier.create(emailService.sendVerificationOtp(TEST_EMAIL, TEST_OTP))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }

    @Nested
    @DisplayName("Send Reset Password OTP")
    class SendResetPasswordOtp {

        @Test
        @DisplayName("Should send reset password email with correct details")
        void shouldSendResetPasswordEmail() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendResetPasswordOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getTo()).containsExactly(TEST_EMAIL);
            assertThat(sentMessage.getFrom()).isEqualTo("noreply@bankingapp.com");
            assertThat(sentMessage.getSubject()).isEqualTo("Reset Password - Banking App");
            assertThat(sentMessage.getText()).contains(TEST_OTP);
            assertThat(sentMessage.getText()).contains("3 minutes");
        }

        @Test
        @DisplayName("Should have different subject than verification email")
        void shouldHaveDifferentSubjectThanVerification() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendResetPasswordOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getSubject()).contains("Reset Password");
            assertThat(messageCaptor.getValue().getSubject()).doesNotContain("Verification");
        }

        @Test
        @DisplayName("Should include security warning in reset email")
        void shouldIncludeSecurityWarning() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendResetPasswordOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getText()).contains("contact support");
        }

        @Test
        @DisplayName("Should handle mail sender exception for reset email")
        void shouldHandleMailSenderExceptionForResetEmail() {
            // Given
            doThrow(new RuntimeException("SMTP connection failed"))
                    .when(mailSender).send(any(SimpleMailMessage.class));

            // When/Then
            StepVerifier.create(emailService.sendResetPasswordOtp(TEST_EMAIL, TEST_OTP))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }

    @Nested
    @DisplayName("Email Content Validation")
    class EmailContentValidation {

        @Test
        @DisplayName("Verification email should mention verification purpose")
        void verificationEmailShouldMentionPurpose() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendVerificationOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getText()).contains("verification");
        }

        @Test
        @DisplayName("Reset email should mention password reset purpose")
        void resetEmailShouldMentionPurpose() {
            // Given
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
            doNothing().when(mailSender).send(any(SimpleMailMessage.class));

            // When
            StepVerifier.create(emailService.sendResetPasswordOtp(TEST_EMAIL, TEST_OTP))
                    .verifyComplete();

            // Then
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getText()).contains("password reset");
        }
    }
}

