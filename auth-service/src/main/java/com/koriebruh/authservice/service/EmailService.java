package com.koriebruh.authservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    /**
     * Kirim OTP ke email user untuk verifikasi.
     * JavaMailSender blocking — di-offload ke boundedElastic.
     *
     * @param toEmail email tujuan
     * @param otp     6 digit OTP
     */
    public Mono<Void> sendVerificationOtp(String toEmail, String otp) {
        return Mono.fromRunnable(() -> {
                    SimpleMailMessage message = new SimpleMailMessage();
                    message.setFrom("noreply@bankingapp.com");
                    message.setTo(toEmail);
                    message.setSubject("Email Verification - Banking App");
                    message.setText("""
                            Your email verification code:
                            
                            %s
                            
                            This code will expire in 5 minutes.
                            If you did not request this, please ignore this email.
                            """.formatted(otp));

                    mailSender.send(message);
                    log.info("Verification OTP sent. email={}", toEmail);
                })
                .subscribeOn(Schedulers.boundedElastic()) // offload blocking mail sender
                .then();
    }
}