package com.koriebruh.authservice.controller;


import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.ApiResponseFactory;
import com.koriebruh.authservice.dto.request.LoginRequest;
import com.koriebruh.authservice.dto.request.MfaSetupVerifyRequest;
import com.koriebruh.authservice.dto.request.RegisterRequest;
import com.koriebruh.authservice.dto.request.VerifyEmailOtpRequest;
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

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {


    @Autowired
    private AuthService authService;

    @Autowired
    private ApiResponseFactory apiResponseFactory;


    public static String getOrGenerateCorrelationId(String correlationId) {
        return correlationId != null ? correlationId : UUID.randomUUID().toString();
    }

    /*
    FLOW NYA YANG BENAR

    POST /register
    POST /verify-email
    POST /login
    → kalau mfaEnabled = false → return accessToken
    → kalau mfaEnabled = true → return mfaToken
    POST /mfa/setup (optional, setelah login)
    POST /mfa/setup/verify
    POST /mfa/verify (saat login jika mfaEnabled)
    */

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




}
