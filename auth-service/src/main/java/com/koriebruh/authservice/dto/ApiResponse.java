package com.koriebruh.authservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

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
}

