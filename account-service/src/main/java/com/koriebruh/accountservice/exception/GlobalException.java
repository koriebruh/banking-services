package com.koriebruh.accountservice.exception;


import com.koriebruh.accountservice.dto.ApiResponse;
import com.koriebruh.accountservice.dto.ApiResponseFactory;
import com.koriebruh.accountservice.filter.CorrelationIdFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Mono;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.util.UUID;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalException {

    private final ApiResponseFactory apiResponseFactory;

    // -------------------------------------------------------------------------
    // HANDLE SPECIFIC BUSINESS EXCEPTIONS
    // -------------------------------------------------------------------------

    /**
     * Handle all AccountExceptions (business errors)
     */
    @ExceptionHandler(AccountExceptions.AccountNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<ApiResponse<Void>> handleNotFound(
            AccountExceptions.AccountNotFoundException ex, ServerWebExchange exchange) {
        log.warn("Account not found: {}", ex.getMessage());
        return Mono.just(apiResponseFactory.error(ex.getMessage(), extractCorrelationId(exchange)));
    }

    @ExceptionHandler({
            AccountExceptions.AccountNumberAlreadyExistsException.class,
            AccountExceptions.AccountTypeAlreadyExistsException.class,
            AccountExceptions.DuplicateSidException.class,
            AccountExceptions.InvalidStatusTransitionException.class,
            AccountExceptions.AccountStatusAlreadySetException.class
    })
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<ApiResponse<Void>> handleConflict(
            AccountExceptions ex, ServerWebExchange exchange) {
        log.warn("Conflict: {}", ex.getMessage());
        return Mono.just(apiResponseFactory.error(ex.getMessage(), extractCorrelationId(exchange)));
    }

    @ExceptionHandler({
            AccountExceptions.InsufficientBalanceException.class,
            AccountExceptions.InsufficientBalanceException.class,
            AccountExceptions.AccountNotActiveException.class,
            AccountExceptions.DepositNotMaturedException.class
    })
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public Mono<ApiResponse<Void>> handleUnprocessable(
            AccountExceptions ex, ServerWebExchange exchange) {
        log.warn("Unprocessable: {}", ex.getMessage());
        return Mono.just(apiResponseFactory.error(ex.getMessage(), extractCorrelationId(exchange)));
    }

    @ExceptionHandler(AccountExceptions.AccountOwnershipException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<ApiResponse<Void>> handleOwnership(
            AccountExceptions.AccountOwnershipException ex, ServerWebExchange exchange) {
        log.warn("Ownership violation: {}", ex.getMessage());
        return Mono.just(apiResponseFactory.error(ex.getMessage(), extractCorrelationId(exchange)));
    }

    @ExceptionHandler(AccountExceptions.AccountNumberGenerationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<ApiResponse<Void>> handleGeneration(
            AccountExceptions.AccountNumberGenerationException ex, ServerWebExchange exchange) {
        log.error("Account number generation failed: {}", ex.getMessage());
        return Mono.just(apiResponseFactory.error(ex.getMessage(), extractCorrelationId(exchange)));
    }


    // -------------------------------------------------------------------------

    @ExceptionHandler(WebExchangeBindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<ApiResponse<Void>> handleValidationException(
            WebExchangeBindException ex,
            ServerWebExchange exchange
    ) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .findFirst()
                .orElse("Validation failed");

        log.warn("Validation failed: {}", message);
        return Mono.just(apiResponseFactory.error(message, extractCorrelationId(exchange)));
    }


    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<ApiResponse<Void>> handleDatabaseConflict(
            DataIntegrityViolationException ex,
            ServerWebExchange exchange
    ) {

        log.error("Database constraint violation", ex);

        return Mono.just(
                apiResponseFactory.error(
                        "Duplicate data detected",
                        extractCorrelationId(exchange)
                )
        );
    }


    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<ApiResponse<Void>> handleGeneralException(
            Exception ex,
            ServerWebExchange exchange
    ) {

        log.error("Unexpected system error", ex);

        return Mono.just(
                apiResponseFactory.error(
                        "Internal server error",
                        extractCorrelationId(exchange)
                )
        );
    }

    /**
     * Handle invalid JSON body — malformed JSON, missing quotes, dll
     * Contoh: kirim refresh_token tanpa quotes, JSON tidak valid
     */
    @ExceptionHandler(ServerWebInputException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<ApiResponse<Void>> handleServerWebInputException(
            ServerWebInputException ex,
            ServerWebExchange exchange
    ) {
        log.warn("Invalid request body: {}", ex.getMessage());
        return Mono.just(
                apiResponseFactory.error(
                        "Invalid request body. Please check your JSON format.",
                        extractCorrelationId(exchange)
                )
        );
    }


    /**
     * Handle Spring Security AccessDeniedException — occurs when authenticated user lacks required role/authority.
     */

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<ApiResponse<Void>> handleAccessDenied(
            AccessDeniedException ex,
            ServerWebExchange exchange) {
        String correlationId = exchange.getRequest().getHeaders()
                .getFirst(CorrelationIdFilter.CORRELATION_ID_HEADER);
        log.warn("Access denied: {}", ex.getMessage());
        return Mono.just(
                apiResponseFactory.error(
                        "Access denied — you do not have permission to perform this action.",
                        correlationId
                )
        );
    }

    /**
     * Extracts X-Correlation-ID from request header.
     * Returns null if not present — ApiResponseFactory handles null gracefully.
     */
    private String extractCorrelationId(ServerWebExchange exchange) {
        return exchange.getRequest()
                .getHeaders()
                .getFirst(CorrelationIdFilter.CORRELATION_ID_HEADER);
    }

}
