package com.koriebruh.authservice.controller;


import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.request.LoginRequest;
import com.koriebruh.authservice.dto.request.RegisterRequest;
import com.koriebruh.authservice.dto.request.VerifyEmailOtpRequest;
import com.koriebruh.authservice.dto.response.LoginResponse;
import com.koriebruh.authservice.dto.response.RegisterResponse;
import com.koriebruh.authservice.dto.response.VerifyEmailOtpResponse;
import com.koriebruh.authservice.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {


    @Autowired
    private AuthService authService;


    public static String getOrGenerateCorrelationId(String correlationId) {
        return correlationId != null ? correlationId : UUID.randomUUID().toString();
    }


    @PostMapping(value = "/register",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<RegisterResponse>> register(
            @RequestBody RegisterRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        // Generate fallback correlationId if not provided (should be rare, as clients should include it)
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);
        return authService.registerUser(request)

                // Transform service result into standardized API response
                .map(registerResponse ->
                        ApiResponse.success(
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
            @RequestBody VerifyEmailOtpRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        String finalCorrelationId = getOrGenerateCorrelationId(correlationId);
        return authService.verifyEmailOtp(request)
                .map( verifyEmailOtpResponse ->
                        ApiResponse.success(
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
            @RequestBody LoginRequest request,
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
                        ApiResponse.success(
                                "Login successful",
                                loginResponse,
                                finalCorrelationId
                        )
                );
    }


}
