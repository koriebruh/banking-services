package com.koriebruh.authservice.controller;


import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.request.RegisterRequest;
import com.koriebruh.authservice.dto.response.RegisterResponse;
import com.koriebruh.authservice.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {


    @Autowired
    private AuthService authService;

    @PostMapping(value = "/register",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ApiResponse<RegisterResponse>> register(
            @RequestBody RegisterRequest request,
            @RequestHeader(name = "X-Correlation-ID", required = false) String correlationId
    ) {
        // Generate fallback correlationId if not provided (should be rare, as clients should include it)
        String finalCorrelationId =
                correlationId != null ? correlationId : java.util.UUID.randomUUID().toString();
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


}
