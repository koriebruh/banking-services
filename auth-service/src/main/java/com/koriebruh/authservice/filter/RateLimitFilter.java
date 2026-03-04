package com.koriebruh.authservice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.koriebruh.authservice.dto.ApiResponse;
import com.koriebruh.authservice.dto.ApiResponseFactory;
import com.koriebruh.authservice.service.RateLimiterService;
import com.koriebruh.authservice.service.RateLimiterService.RateLimitResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Banking-grade Rate Limit Filter implementing security best practices.
 *
 * <p>Features aligned with PCI-DSS & OWASP:
 * <ul>
 *   <li>IP Spoofing protection (validates X-Forwarded-For)</li>
 *   <li>Standard X-RateLimit-* headers for API consumers</li>
 *   <li>Retry-After header for 429 responses</li>
 *   <li>Trusted proxy validation</li>
 * </ul>
 */
@Slf4j
@Component
@Order(1)
@RequiredArgsConstructor
public class RateLimitFilter implements WebFilter {

    private final RateLimiterService rateLimiterService;
    private final ObjectMapper objectMapper;
    private final ApiResponseFactory apiResponseFactory;

    // Trusted proxy CIDRs (internal networks) - configure based on your infrastructure
    private static final Set<String> TRUSTED_PROXY_PREFIXES = Set.of(
            "10.",       // Private Class A
            "172.16.",   // Private Class B (172.16.0.0 - 172.31.255.255)
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.", // Private Class C
            "127."      // Localhost
    );

    // IP validation pattern
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    /**
     * Maps URL path segments to rate limit config keys.
     * Keys must match those defined under {@code app.rate-limit.endpoints} in application.yml.
     */
    private static final Map<String, String> PATH_TO_KEY = Map.of(
            "/login",               "login",
            "/register",            "register",
            "/verify-email",        "verify-email",
            "/resend-verification", "resend-verification",
            "/forgot-password",     "forgot-password",
            "/reset-password",      "reset-password",
            "/mfa/validate",        "mfa-validate",
            "/refresh",             "refresh"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        String ipAddress = resolveIpAddress(exchange);

        String endpointKey = PATH_TO_KEY.entrySet().stream()
                .filter(entry -> path.contains(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);

        // Path not in rate-limit map — skip
        if (endpointKey == null) {
            return chain.filter(exchange);
        }

        return rateLimiterService.checkRateLimit(ipAddress, endpointKey)
                .flatMap(result -> {
                    // Add rate limit headers to response (standard practice)
                    addRateLimitHeaders(exchange.getResponse(), result);

                    if (!result.isAllowed()) {
                        return rejectRequest(exchange, ipAddress, endpointKey, result);
                    }
                    return chain.filter(exchange);
                });
    }

    /**
     * Adds standard X-RateLimit headers to response.
     * This is API best practice and helps legitimate clients manage their request rate.
     */
    private void addRateLimitHeaders(ServerHttpResponse response, RateLimitResult result) {
        response.getHeaders().add("X-RateLimit-Limit", String.valueOf(result.getMaxRequests()));
        response.getHeaders().add("X-RateLimit-Remaining", String.valueOf(Math.max(0, result.getRemaining())));
        response.getHeaders().add("X-RateLimit-Window", result.getWindowSeconds() + "s");
    }

    /**
     * Resolves the real client IP address with spoofing protection.
     *
     * <p>Security measures:
     * <ul>
     *   <li>Only trusts X-Forwarded-For from known proxy networks</li>
     *   <li>Validates IP format to prevent injection</li>
     *   <li>Falls back to direct connection IP if headers are suspicious</li>
     * </ul>
     */
    private String resolveIpAddress(ServerWebExchange exchange) {
        var remoteAddress = exchange.getRequest().getRemoteAddress();
        String directIp = remoteAddress != null
                ? remoteAddress.getAddress().getHostAddress()
                : "unknown";

        // Only trust X-Forwarded-For if request comes from trusted proxy
        if (!isFromTrustedProxy(directIp)) {
            return directIp;
        }

        String forwarded = exchange.getRequest()
                .getHeaders()
                .getFirst("X-Forwarded-For");

        if (forwarded == null || forwarded.isBlank()) {
            return directIp;
        }

        // X-Forwarded-For format: "client, proxy1, proxy2"
        // Take the leftmost (original client) IP
        String clientIp = forwarded.split(",")[0].trim();

        // Validate IP format to prevent header injection attacks
        if (!isValidIpAddress(clientIp)) {
            log.warn("[RATE-LIMIT][SECURITY] Invalid X-Forwarded-For value detected. value={}, directIp={}",
                    sanitizeForLog(forwarded), directIp);
            return directIp;
        }

        return clientIp;
    }

    /**
     * Checks if the direct connection IP is from a trusted proxy network.
     */
    private boolean isFromTrustedProxy(String ip) {
        if (ip == null || ip.equals("unknown")) {
            return false;
        }
        return TRUSTED_PROXY_PREFIXES.stream().anyMatch(ip::startsWith);
    }

    /**
     * Validates IP address format (IPv4).
     * Prevents header injection attacks via malformed X-Forwarded-For.
     */
    private boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isBlank() || ip.length() > 45) { // Max IPv6 length
            return false;
        }

        // Check IPv4
        if (IPV4_PATTERN.matcher(ip).matches()) {
            return true;
        }

        // Check IPv6 (basic validation)
        try {
            InetAddress.getByName(ip);
            return ip.contains(":");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Sanitizes string for logging to prevent log injection attacks.
     */
    private String sanitizeForLog(String input) {
        if (input == null) return "null";
        return input.replaceAll("[\\r\\n]", "_")
                    .substring(0, Math.min(input.length(), 100));
    }

    /**
     * Returns a standardised 429 Too Many Requests response.
     * Includes Retry-After header as per RFC 6585.
     */
    private Mono<Void> rejectRequest(ServerWebExchange exchange, String ip, String endpointKey, RateLimitResult result) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // RFC 6585: Retry-After header tells client when to retry
        response.getHeaders().add("Retry-After", String.valueOf(result.getWindowSeconds()));

        String requestId = UUID.randomUUID().toString();

        ApiResponse<Void> body = apiResponseFactory.error(
                "Too many requests. Please try again in " + result.getWindowSeconds() + " seconds.",
                requestId
        );

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("[RATE-LIMIT][ERROR] Failed to write response. requestId={}", requestId, e);
            return response.setComplete();
        }
    }
}