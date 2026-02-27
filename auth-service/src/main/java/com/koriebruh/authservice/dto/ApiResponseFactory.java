package com.koriebruh.authservice.dto;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Map;


@Component
@RequiredArgsConstructor
public class ApiResponseFactory {

    @Value("${spring.application.name}")
    private String serviceName;

    @Value("${app.version}")
    private String version;

    public <T> ApiResponse<T> success(String message, T data, String correlationId) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .meta(ApiResponse.Meta.builder()
                        .timestamp(ZonedDateTime.now())
                        .correlationId(correlationId)
                        .service(serviceName)
                        .version(version)
                        .build())
                .build();
    }

    public <T> ApiResponse<T> error(String message, String correlationId) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .meta(ApiResponse.Meta.builder()
                        .timestamp(ZonedDateTime.now())
                        .correlationId(correlationId)
                        .service(serviceName)
                        .version(version)
                        .build())
                .build();
    }

    public <T> ApiResponse<T> error(String message,
                                    Map<String, String> fieldErrors,
                                    String correlationId) {

        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .data(null)
                .errors(fieldErrors)
                .meta(ApiResponse.Meta.builder()
                        .timestamp(ZonedDateTime.now())
                        .correlationId(correlationId)
                        .service(serviceName)
                        .version(version)
                        .build())
                .build();
    }

}
