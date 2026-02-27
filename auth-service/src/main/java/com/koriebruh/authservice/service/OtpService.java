package com.koriebruh.authservice.service;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Slf4j
@Service
public class OtpService {

    @Value("${spring.application.name}")
    private String ISSUER;

    private static final int OTP_LENGTH = 6;
    private static final int TIME_PERIOD = 30;

    /**
     * Generate random TOTP secret key untuk user.
     * Secret ini disimpan di DB — sebaiknya diencrypt di production.
     */
    public String generateSecret() {
        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        return secretGenerator.generate();
    }

    /**
     * Generate QR code sebagai base64 PNG string.
     * QR code di-generate di server — secret TIDAK pernah dikirim ke pihak ketiga.
     * Frontend render dengan: <img src="data:image/png;base64,{qrCode}" />
     *
     * @param email  email user (label di authenticator app)
     * @param secret secret key yang sudah disimpan di DB
     * @return base64 encoded PNG image
     */
    public String generateQrCodeBase64(String email, String secret) throws QrGenerationException {
        QrData data = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(OTP_LENGTH)
                .period(TIME_PERIOD)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = generator.generate(data);

        // Encode ke base64 — secret tidak pernah keluar dari server
        return Base64.getEncoder().encodeToString(imageData);
    }

    /**
     * Verify OTP code yang diinput user terhadap secret key-nya.
     * Window = 1 untuk toleransi clock skew ±30 detik antara server dan device.
     *
     * @param secret  secret key user dari DB
     * @param otpCode 6 digit OTP dari Google Authenticator
     * @return true jika valid
     */
    public boolean verifyOtp(String secret, String otpCode) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, OTP_LENGTH);
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setTimePeriod(TIME_PERIOD);
        verifier.setAllowedTimePeriodDiscrepancy(1);
        return verifier.isValidCode(secret, otpCode);
    }

}
