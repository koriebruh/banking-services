package com.koriebruh.authservice.service;

import com.koriebruh.authservice.config.RateLimitConfig;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Banking-grade Rate Limiter Service implementing PCI-DSS & OWASP security best practices.
 *
 * <p>Features:
 * <ul>
 *   <li>Atomic Sliding Window using Redis Lua Script (prevents race conditions)</li>
 *   <li>Unique request IDs to handle concurrent requests accurately</li>
 *   <li>Detailed audit logging for compliance</li>
 *   <li>Remaining limit info for response headers</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimiterService {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RateLimitConfig rateLimitConfig;

    private static final String KEY_PREFIX = "rate-limit:";

    // Counter for unique member generation (nano precision + counter for uniqueness)
    private final AtomicLong requestCounter = new AtomicLong(0);

    /**
     * Lua script for atomic sliding window rate limiting.
     * This ensures all operations (remove, count, add, expire) happen atomically,
     * preventing race conditions that could allow burst attacks.
     *
     * KEYS[1] = rate limit key
     * ARGV[1] = window start timestamp
     * ARGV[2] = current timestamp (score)
     * ARGV[3] = unique member ID
     * ARGV[4] = max requests allowed
     * ARGV[5] = window TTL in seconds
     *
     * Returns: [allowed (0/1), current_count, remaining]
     */
    private static final String RATE_LIMIT_LUA_SCRIPT = """
        local key = KEYS[1]
        local windowStart = tonumber(ARGV[1])
        local now = tonumber(ARGV[2])
        local member = ARGV[3]
        local maxRequests = tonumber(ARGV[4])
        local windowTTL = tonumber(ARGV[5])
        
        -- Remove expired entries (outside sliding window)
        redis.call('ZREMRANGEBYSCORE', key, 0, windowStart)
        
        -- Count current requests in window
        local currentCount = redis.call('ZCARD', key)
        
        -- Check if limit exceeded
        if currentCount >= maxRequests then
            return {0, currentCount, 0}
        end
        
        -- Add new request with unique member
        redis.call('ZADD', key, now, member)
        
        -- Set expiry
        redis.call('EXPIRE', key, windowTTL)
        
        -- Return allowed, count after add, remaining
        local newCount = currentCount + 1
        local remaining = maxRequests - newCount
        return {1, newCount, remaining}
        """;

    /**
     * Result object containing rate limit check outcome with metadata.
     */
    @Data
    @Builder
    public static class RateLimitResult {
        private final boolean allowed;
        private final long currentCount;
        private final long remaining;
        private final int maxRequests;
        private final int windowSeconds;
    }

    /**
     * Checks whether the given IP address has exceeded the rate limit for the specified endpoint.
     *
     * <p>Uses an atomic Sliding Window algorithm backed by Redis Lua Script:
     * <ul>
     *   <li>All operations are atomic - prevents race condition exploits</li>
     *   <li>Each request has unique ID - handles concurrent requests accurately</li>
     *   <li>Returns detailed result for response headers (X-RateLimit-*)</li>
     * </ul>
     *
     * <p>Key format: {@code rate-limit:<endpointKey>:<ipAddress>}
     *
     * @param ipAddress   the originating IP address (validated, not raw X-Forwarded-For)
     * @param endpointKey the endpoint identifier matching keys in {@code app.rate-limit.endpoints}
     * @return {@link RateLimitResult} containing allowed status and metadata
     */
    public Mono<RateLimitResult> checkRateLimit(String ipAddress, String endpointKey) {
        RateLimitConfig.EndpointLimit limit = rateLimitConfig.getEndpoints().get(endpointKey);

        if (limit == null) {
            log.warn("[RATE-LIMIT] No config found. endpoint={}, ip={}", endpointKey, maskIp(ipAddress));
            return Mono.just(RateLimitResult.builder()
                    .allowed(true)
                    .currentCount(0)
                    .remaining(Integer.MAX_VALUE)
                    .maxRequests(Integer.MAX_VALUE)
                    .windowSeconds(0)
                    .build());
        }

        String key = KEY_PREFIX + endpointKey + ":" + ipAddress;
        long now = Instant.now().toEpochMilli();
        long windowStart = now - Duration.ofSeconds(limit.getWindowSeconds()).toMillis();

        // Generate unique member: timestamp_counter_uuid (handles concurrent requests)
        String uniqueMember = now + "_" + requestCounter.incrementAndGet() + "_" + UUID.randomUUID().toString().substring(0, 8);

        RedisScript<java.util.List> script = RedisScript.of(RATE_LIMIT_LUA_SCRIPT, java.util.List.class);

        return redisTemplate.execute(
                script,
                Collections.singletonList(key),
                String.valueOf(windowStart),
                String.valueOf(now),
                uniqueMember,
                String.valueOf(limit.getMaxRequests()),
                String.valueOf(limit.getWindowSeconds())
        )
        .next()
        .map(result -> {
            @SuppressWarnings("unchecked")
            java.util.List<Long> resultList = (java.util.List<Long>) result;

            boolean allowed = resultList.get(0) == 1L;
            long currentCount = resultList.get(1);
            long remaining = resultList.get(2);

            // Audit logging for security compliance (PCI-DSS requirement)
            if (!allowed) {
                log.warn("[RATE-LIMIT][BLOCKED] endpoint={}, ip={}, count={}/{}, window={}s",
                        endpointKey, maskIp(ipAddress), currentCount, limit.getMaxRequests(), limit.getWindowSeconds());
            } else if (currentCount > (limit.getMaxRequests() * 0.8)) {
                // Warning when approaching limit (80% threshold)
                log.info("[RATE-LIMIT][WARNING] Approaching limit. endpoint={}, ip={}, count={}/{}",
                        endpointKey, maskIp(ipAddress), currentCount, limit.getMaxRequests());
            }

            return RateLimitResult.builder()
                    .allowed(allowed)
                    .currentCount(currentCount)
                    .remaining(remaining)
                    .maxRequests(limit.getMaxRequests())
                    .windowSeconds(limit.getWindowSeconds())
                    .build();
        })
        .defaultIfEmpty(RateLimitResult.builder()
                .allowed(true)
                .currentCount(0)
                .remaining(limit.getMaxRequests())
                .maxRequests(limit.getMaxRequests())
                .windowSeconds(limit.getWindowSeconds())
                .build());
    }

    /**
     * Simple boolean check for backward compatibility.
     *
     * @param ipAddress   the originating IP address
     * @param endpointKey the endpoint identifier
     * @return {@code true} if allowed, {@code false} if rate limited
     */
    public Mono<Boolean> isAllowed(String ipAddress, String endpointKey) {
        return checkRateLimit(ipAddress, endpointKey)
                .map(RateLimitResult::isAllowed);
    }

    /**
     * Masks IP address for logging (PCI-DSS compliance - don't log full PII).
     * Example: 192.168.1.100 -> 192.168.x.x
     */
    private String maskIp(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return "unknown";
        }

        // IPv4 masking
        if (ipAddress.contains(".")) {
            String[] parts = ipAddress.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + ".x.x";
            }
        }

        // IPv6 masking (show first 2 segments)
        if (ipAddress.contains(":")) {
            String[] parts = ipAddress.split(":");
            if (parts.length >= 2) {
                return parts[0] + ":" + parts[1] + ":x:x:x:x:x:x";
            }
        }

        return "masked";
    }
}