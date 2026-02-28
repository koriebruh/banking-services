package com.koriebruh.authservice.exception;


import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.ApiResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptions {

    private final ApiResponseFactory apiResponseFactory;

    /**
     * Handle all UserExceptions (business errors)
     */
    @ExceptionHandler(UserExceptions.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<ApiResponse<Void>> handleUserExceptions(UserExceptions ex) {

        log.warn("Business exception occurred: {}", ex.getMessage());

        return Mono.just(
                apiResponseFactory.error(
                        ex.getMessage(),
                        generateCorrelationId()
                )
        );
    }

    /**
     * Handle validation errors (@Valid annotation failures)
     * Contoh: otp_code bukan 6 digit, email format salah, dll
     */
    @ExceptionHandler(WebExchangeBindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<ApiResponse<Void>> handleValidationException(WebExchangeBindException ex) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .findFirst()
                .orElse("Validation failed");

        log.warn("Validation failed: {}", message);
        return Mono.just(apiResponseFactory.error(message, generateCorrelationId()));
    }

    /**
     * Handle database constraint violations (race condition fallback)
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<ApiResponse<Void>> handleDatabaseConflict(
            DataIntegrityViolationException ex
    ) {

        log.error("Database constraint violation", ex);

        return Mono.just(
                apiResponseFactory.error(
                        "Duplicate data detected",
                        generateCorrelationId()
                )
        );
    }

    /**
     * Catch all unexpected errors
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<ApiResponse<Void>> handleGeneralException(Exception ex) {

        log.error("Unexpected system error", ex);

        return Mono.just(
                apiResponseFactory.error(
                        "Internal server error",
                        generateCorrelationId()
                )
        );
    }

    /**
     * Temporary correlationId generator.
     * In production, inject from WebFilter instead.
     */
    private String generateCorrelationId() {
        return UUID.randomUUID().toString();
    }
}
