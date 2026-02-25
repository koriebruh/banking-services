package com.koriebruh.authservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;
import java.util.Map;

/**
 * Generic API response wrapper following best practices for microservices.
 * @param <T> The type of data being returned
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private boolean success;

    private String message;

    private T data;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Map<String, String> errors;

    private Meta meta;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Meta {
        private ZonedDateTime timestamp;

        @JsonProperty("correlation_id")
        private String correlationId;

        private String service;

        private String version;
    }

    // Static factory methods for convenience
    public static <T> ApiResponse<T> success(String message, T data, String correlationId) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .meta(Meta.builder()
                        .timestamp(ZonedDateTime.now())
                        .correlationId(correlationId)
                        .service("auth-service")
                        .version("v1")
                        .build())
                .build();
    }

    public static <T> ApiResponse<T> error(String message, Map<String, String> errors, String correlationId) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .errors(errors)
                .meta(Meta.builder()
                        .timestamp(ZonedDateTime.now())
                        .correlationId(correlationId)
                        .service("auth-service")
                        .version("v1")
                        .build())
                .build();
    }

    public static <T> ApiResponse<T> error(String message, String correlationId) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .meta(Meta.builder()
                        .timestamp(ZonedDateTime.now())
                        .correlationId(correlationId)
                        .service("auth-service")
                        .version("v1")
                        .build())
                .build();
    }
}

