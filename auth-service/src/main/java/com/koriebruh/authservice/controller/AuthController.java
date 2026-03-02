package com.koriebruh.authservice.controller;


import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.ApiResponseFactory;
import com.koriebruh.authservice.dto.request.*;
import com.koriebruh.authservice.dto.response.*;
import com.koriebruh.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Banking authentication endpoints")
public class AuthController {


    @Autowired
    private AuthService authService;

    @Autowired
    private ApiResponseFactory apiResponseFactory;


    public static String getOrGenerateCorrelationId(String correlationId) {
        return correlationId != null ? correlationId : UUID.randomUUID().toString();
    }


    @Operation(summary = "Register new user", description = "Register a new banking user account")
    @PostMapping(value = "/register",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<RegisterResponse>> register(
            @RequestBody @Valid RegisterRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        // Generate fallback correlationId if not provided (should be rare, as clients should include it)
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);
        return authService.registerUser(request)

                // Transform service result into standardized API response
                .map(registerResponse ->
                        apiResponseFactory.success(
                                "User registered successfully",
                                registerResponse,
                                finalCorrelationId
                        )
                );
    }

    @Operation(summary = "Verify email OTP", description = "Verify email with OTP sent to user's email")
    @PostMapping(value = "/verify-email",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<VerifyEmailOtpResponse>> verifyEmailOtp(
            @RequestBody @Valid VerifyEmailOtpRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);
        return authService.verifyEmailOtp(request)
                .map(verifyEmailOtpResponse ->
                        apiResponseFactory.success(
                                "Email OTP verification successful",
                                verifyEmailOtpResponse,
                                finalCorrelationId
                        )
                );
    }

    @Operation(summary = "Resend verification OTP")
    @PostMapping(value = "/resend-verification",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<Void>> resendVerification(
            @RequestBody @Valid ResendVerificationRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return authService.resendVerification(request)
                .thenReturn(apiResponseFactory.success(
                        "If your email is registered and not yet verified, a new verification code has been sent.",
                        null,
                        finalCorrelationId
                ));
    }


    @Operation(summary = "Login", description = "Login with email and password")
    @PostMapping(value = "/login",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<LoginResponse>> login(
            @RequestBody @Valid LoginRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId,
            ServerHttpRequest httpRequest
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        String ipAddress = httpRequest.getRemoteAddress() != null
                ? httpRequest.getRemoteAddress().getAddress().getHostAddress()
                : "UNKNOWN";

        String userAgent = httpRequest.getHeaders().getFirst("User-Agent");

        return authService.loginUser(request, ipAddress, userAgent)
                .map(loginResponse ->
                        apiResponseFactory.success(
                                "Login successful",
                                loginResponse,
                                finalCorrelationId
                        )
                );
    }


    @Operation(summary = "MFA Setup", description = "Generate QR code for Google Authenticator setup")
    @PostMapping(value = "/mfa/setup",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<MfaSetupResponse>> setupMfa(
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal().toString())
                .flatMap(userId -> authService.setupMfa(userId))
                .map(setupResponse ->
                        apiResponseFactory.success(
                                "MFA setup initiated. Please scan the QR code with Google Authenticator.",
                                setupResponse,
                                finalCorrelationId
                        )
                );
    }

    @Operation(summary = "MFA Setup Verify", description = "Confirm first OTP to activate MFA")
    @PostMapping(value = "/mfa/setup/verify",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<MfaSetupVerifyResponse>> verifyMfaSetup(
            @RequestBody @Valid MfaSetupVerifyRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal().toString())
                .flatMap(userId -> authService.verifyMfaSetup(userId, request))
                .map(response ->
                        apiResponseFactory.success(
                                "MFA setup verified successfully.",
                                response,
                                finalCorrelationId
                        )
                );
    }

    @Operation(summary = "MFA Validate", description = "Exchange MFA token + OTP for access token")
    @PostMapping(value = "/mfa/validate",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<MfaValidateResponse>> validateMfa(
            @RequestBody @Valid MfaValidateRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId,
            ServerHttpRequest httpRequest
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        String ipAddress = httpRequest.getRemoteAddress() != null
                ? httpRequest.getRemoteAddress().getAddress().getHostAddress()
                : "UNKNOWN";

        String userAgent = httpRequest.getHeaders().getFirst("User-Agent");

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal().toString())
                .flatMap(userId -> authService.validateMfa(userId, request, ipAddress, userAgent))
                .map(response ->
                        apiResponseFactory.success(
                                "MFA validated successfully.",
                                response,
                                finalCorrelationId
                        )
                );
    }


    @Operation(summary = "Logout", description = "Revoke refresh token")
    @PostMapping(value = "/logout",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<Void>> logout(
            @RequestBody @Valid LogoutRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal().toString())
                .flatMap(userId -> authService.logout(userId, request))
                .thenReturn(apiResponseFactory.success(
                        "Logged out successfully.",
                        null,
                        finalCorrelationId
                ));
    }


    @Operation(summary = "Refresh Token", description = "Exchange refresh token for new access token")
    @PostMapping(value = "/refresh",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<RefreshTokenResponse>> refreshToken(
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId,
            @RequestHeader(name = "Authorization") String authorizationHeader // ← ambil dari header
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        String rawRefreshToken = authorizationHeader.substring(7);

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal().toString())
                .flatMap(userId -> authService.refreshToken(userId, rawRefreshToken))
                .map(response ->
                        apiResponseFactory.success(
                                "Token refreshed successfully.",
                                response,
                                finalCorrelationId
                        )
                );
    }

    @Operation(summary = "Change Password")
    @PostMapping(value = "/change-password",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<Void>> changePassword(
            @RequestBody @Valid ChangePasswordRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal().toString())
                .flatMap(userId -> authService.changePassword(userId, request))
                .thenReturn(apiResponseFactory.success(
                        "Password changed successfully. Please login again.",
                        null,
                        finalCorrelationId
                ));
    }

    @Operation(summary = "Forgot Password", description = "Send OTP to email for password reset")
    @PostMapping(value = "/forgot-password",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<Void>> forgotPassword(
            @RequestBody @Valid ForgotPasswordRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return authService.forgotPassword(request)
                .thenReturn(apiResponseFactory.success(
                        // Pesan generic — tidak expose apakah email terdaftar
                        "If your email is registered, you will receive a password reset code.",
                        null,
                        finalCorrelationId
                ));
    }


    @Operation(summary = "Reset Password", description = "Reset password using OTP from email")
    @PostMapping(value = "/reset-password",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<Void>> resetPassword(
            @RequestBody @Valid ResetPasswordRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);

        return authService.resetPassword(request)
                .thenReturn(apiResponseFactory.success(
                        "Password reset successfully. Please login with your new password.",
                        null,
                        finalCorrelationId
                ));
    }

}
