package com.koriebruh.accountservice.controller;


import com.koriebruh.accountservice.dto.ApiResponse;
import com.koriebruh.accountservice.dto.ApiResponseFactory;
import com.koriebruh.accountservice.dto.request.OpenAccountRequest;
import com.koriebruh.accountservice.dto.request.UpdateAccountStatusRequest;
import com.koriebruh.accountservice.dto.response.AccountResponse;
import com.koriebruh.accountservice.service.AccountService;
import com.koriebruh.accountservice.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/accounts")
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    private final ApiResponseFactory apiResponseFactory;

    private final JwtUtil jwtUtil;


    /**
     * Opens a new bank account for the authenticated user.
     *
     * <p><b>Flow:</b> extract userId + userCode from JWT → delegate to AccountService
     * <p><b>Security:</b> any authenticated user (CUSTOMER or ADMIN) can open an account.
     *
     * @param authHeader raw Authorization header value
     * @param request    validated open account request body
     * @return 201 with opened account detail
     */
    @PostMapping(
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ApiResponse<AccountResponse>> openAccount(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @RequestHeader(name = "X-Correlation-ID") String correlationId,
            @RequestBody @Valid OpenAccountRequest request
    ) {
        String token = extractToken(authHeader);
        UUID userId = jwtUtil.extractUserId(token);
        String userCode = jwtUtil.extractUserCode(token);

        return accountService.openAccount(request, userId, userCode)
                .map(response ->
                        apiResponseFactory.success(
                                "Account opened successfully",
                                response,
                                correlationId
                        )
                );
    }


    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<ApiResponse<List<AccountResponse>>> getMyAccounts(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @RequestHeader(name = "X-Correlation-ID") String correlationId
    ) {
        String token = extractToken(authHeader);
        UUID userId = jwtUtil.extractUserId(token);

        return accountService.getMyAccounts(userId)
                .collectList()
                .map(accounts -> apiResponseFactory.success(
                        "Accounts retrieved successfully",
                        accounts,
                        correlationId
                ));
    }

    @GetMapping(
            value = "/{accountNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    public Mono<ApiResponse<AccountResponse>> getAccountDetail(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @RequestHeader(name = "X-Correlation-ID") String correlationId,
            @PathVariable String accountNumber
    ) {
        String token = extractToken(authHeader);
        UUID userId = jwtUtil.extractUserId(token);

        return accountService.getAccountDetail(accountNumber, userId)
                .map(account -> apiResponseFactory.success(
                        "Account detail retrieved successfully",
                        account,
                        correlationId
                ));
    }

    @PatchMapping(
            value = "/{accountNumber}/status",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.OK)
    public Mono<ApiResponse<AccountResponse>> updateAccountStatus(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @RequestHeader(name = "X-Correlation-ID") String correlationId,
            @PathVariable String accountNumber,
            @RequestBody @Valid UpdateAccountStatusRequest request
    ) {
        String token = extractToken(authHeader);
        String userCode = jwtUtil.extractUserCode(token);

        return accountService.updateAccountStatus(accountNumber, request, userCode)
                .map(response -> apiResponseFactory.success(
                        "Account status updated",
                        response,
                        correlationId
                ));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Strips "Bearer " prefix from the Authorization header.
     * Filter has already validated the token before this point.
     *
     * @param authHeader raw Authorization header value
     * @return raw JWT string
     */
    private String extractToken(String authHeader) {
        return authHeader.substring(7);
    }

}
