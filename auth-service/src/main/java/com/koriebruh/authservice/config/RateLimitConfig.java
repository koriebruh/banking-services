package com.koriebruh.authservice.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "app.rate-limit")
public class RateLimitConfig {

    private Map<String, EndpointLimit> endpoints;

    @Data
    public static class EndpointLimit {
        private int maxRequests;
        private int windowSeconds;
    }
}