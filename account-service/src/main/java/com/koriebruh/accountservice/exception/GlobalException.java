package com.koriebruh.accountservice.exception;


import com.koriebruh.accountservice.dto.ApiResponse;
import com.koriebruh.accountservice.dto.ApiResponseFactory;
import com.koriebruh.accountservice.filter.CorrelationIdFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
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

    /**
     * Handle all AccountExceptions (business errors)
     */
    @ExceptionHandler(AccountExceptions.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<ApiResponse<Void>> handleUserExceptions(
            AccountExceptions ex,
            ServerWebExchange exchange
    ) {

        log.warn("Business exception occurred: {}", ex.getMessage());

        return Mono.just(
                apiResponseFactory.error(
                        ex.getMessage(),
                        extractCorrelationId(exchange)
                )
        );
    }


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
     * Extracts X-Correlation-ID from request header.
     * Returns null if not present — ApiResponseFactory handles null gracefully.
     */
    private String extractCorrelationId(ServerWebExchange exchange) {
        return exchange.getRequest()
                .getHeaders()
                .getFirst(CorrelationIdFilter.CORRELATION_ID_HEADER);
    }

}
