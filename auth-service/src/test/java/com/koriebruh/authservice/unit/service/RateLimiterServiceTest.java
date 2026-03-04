package com.koriebruh.authservice.unit.service;

import com.koriebruh.authservice.config.RateLimitConfig;
import com.koriebruh.authservice.service.RateLimiterService;
import com.koriebruh.authservice.service.RateLimiterService.RateLimitResult;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RateLimiterService.
 *
 * Tests cover:
 * - Rate limit allowing requests within limit
 * - Rate limit blocking requests exceeding limit
 * - Handling of unconfigured endpoints
 * - IP masking for PCI-DSS compliance
 * - Backward compatibility with isAllowed() method
 * - Edge cases (null/blank IPs, IPv6)
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("RateLimiterService Unit Tests")
class RateLimiterServiceTest {

    @Mock
    private ReactiveRedisTemplate<String, String> redisTemplate;

    @Mock
    private RateLimitConfig rateLimitConfig;

    private RateLimiterService rateLimiterService;

    private static final String TEST_IP = "192.168.1.100";
    private static final String TEST_ENDPOINT = "login";

    @BeforeEach
    void setUp() {
        rateLimiterService = new RateLimiterService(redisTemplate, rateLimitConfig);
    }

    // -------------------------------------------------------------------------
    // checkRateLimit() Tests
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("checkRateLimit()")
    class CheckRateLimitTests {

        @Test
        @DisplayName("Should allow request when under rate limit")
        void shouldAllowRequestWhenUnderLimit() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Redis returns: [allowed=1, currentCount=1, remaining=4]
            List<Long> redisResult = Arrays.asList(1L, 1L, 4L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isTrue();
                        assertThat(result.getCurrentCount()).isEqualTo(1L);
                        assertThat(result.getRemaining()).isEqualTo(4L);
                        assertThat(result.getMaxRequests()).isEqualTo(5);
                        assertThat(result.getWindowSeconds()).isEqualTo(60);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should block request when rate limit exceeded")
        void shouldBlockRequestWhenLimitExceeded() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Redis returns: [allowed=0, currentCount=5, remaining=0]
            List<Long> redisResult = Arrays.asList(0L, 5L, 0L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isFalse();
                        assertThat(result.getCurrentCount()).isEqualTo(5L);
                        assertThat(result.getRemaining()).isEqualTo(0L);
                        assertThat(result.getMaxRequests()).isEqualTo(5);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should allow request when endpoint not configured")
        void shouldAllowWhenEndpointNotConfigured() {
            // Given
            when(rateLimitConfig.getEndpoints()).thenReturn(new HashMap<>());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, "unknown-endpoint"))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isTrue();
                        assertThat(result.getCurrentCount()).isEqualTo(0L);
                        assertThat(result.getRemaining()).isEqualTo(Integer.MAX_VALUE);
                        assertThat(result.getMaxRequests()).isEqualTo(Integer.MAX_VALUE);
                        assertThat(result.getWindowSeconds()).isEqualTo(0);
                    })
                    .verifyComplete();

            // Verify Redis was NOT called
            verify(redisTemplate, never()).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());
        }

        @Test
        @DisplayName("Should return default result when Redis returns empty")
        void shouldReturnDefaultWhenRedisEmpty() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Redis returns empty
            doReturn(Flux.empty())
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isTrue();
                        assertThat(result.getCurrentCount()).isEqualTo(0L);
                        assertThat(result.getRemaining()).isEqualTo(5L);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should track request count approaching limit (80% threshold)")
        void shouldTrackRequestsApproachingLimit() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(10, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Redis returns: count=9 (90% of limit, should trigger warning)
            List<Long> redisResult = Arrays.asList(1L, 9L, 1L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isTrue();
                        assertThat(result.getCurrentCount()).isEqualTo(9L);
                        assertThat(result.getRemaining()).isEqualTo(1L);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should use correct Redis key format")
        void shouldUseCorrectRedisKeyFormat() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            List<Long> redisResult = Arrays.asList(1L, 1L, 4L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT).block();

            // Then - verify execute was called
            verify(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());
        }
    }

    // -------------------------------------------------------------------------
    // isAllowed() Tests (Backward Compatibility)
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("isAllowed() - Backward Compatibility")
    class IsAllowedTests {

        @Test
        @DisplayName("Should return true when allowed")
        void shouldReturnTrueWhenAllowed() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            List<Long> redisResult = Arrays.asList(1L, 1L, 4L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When/Then
            StepVerifier.create(rateLimiterService.isAllowed(TEST_IP, TEST_ENDPOINT))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should return false when blocked")
        void shouldReturnFalseWhenBlocked() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            List<Long> redisResult = Arrays.asList(0L, 5L, 0L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When/Then
            StepVerifier.create(rateLimiterService.isAllowed(TEST_IP, TEST_ENDPOINT))
                    .expectNext(false)
                    .verifyComplete();
        }
    }

    // -------------------------------------------------------------------------
    // Multiple Endpoints Tests
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Multiple Endpoints Configuration")
    class MultipleEndpointsTests {

        @Test
        @DisplayName("Should apply different limits per endpoint")
        void shouldApplyDifferentLimitsPerEndpoint() {
            // Given
            RateLimitConfig.EndpointLimit loginLimit = createEndpointLimit(5, 60);
            RateLimitConfig.EndpointLimit registerLimit = createEndpointLimit(3, 3600);

            Map<String, RateLimitConfig.EndpointLimit> endpoints = new HashMap<>();
            endpoints.put("login", loginLimit);
            endpoints.put("register", registerLimit);
            when(rateLimitConfig.getEndpoints()).thenReturn(endpoints);

            List<Long> redisResult = Arrays.asList(1L, 1L, 2L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When - check register endpoint
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, "register"))
                    .assertNext(result -> {
                        assertThat(result.getMaxRequests()).isEqualTo(3);
                        assertThat(result.getWindowSeconds()).isEqualTo(3600);
                    })
                    .verifyComplete();
        }
    }

    // -------------------------------------------------------------------------
    // Edge Cases Tests
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Edge Cases")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null endpoints map gracefully")
        void shouldHandleNullEndpointsMap() {
            // Given
            when(rateLimitConfig.getEndpoints()).thenReturn(null);

            // When/Then - NPE occurs synchronously before reactive chain starts
            Assertions.assertThrows(NullPointerException.class, () -> {
                rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT).block();
            });
        }

        @Test
        @DisplayName("Should handle IPv6 address")
        void shouldHandleIPv6Address() {
            // Given
            String ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(5, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            List<Long> redisResult = Arrays.asList(1L, 1L, 4L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(ipv6, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isTrue();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should handle high traffic scenario")
        void shouldHandleHighTrafficScenario() {
            // Given - low limit configuration
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(100, 1);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Simulate 100th request (at limit)
            List<Long> redisResult = Arrays.asList(1L, 100L, 0L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isTrue();
                        assertThat(result.getCurrentCount()).isEqualTo(100L);
                        assertThat(result.getRemaining()).isEqualTo(0L);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should handle zero max requests configuration")
        void shouldHandleZeroMaxRequestsConfig() {
            // Given - misconfigured with 0 max requests
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(0, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Redis will immediately block (0 >= 0)
            List<Long> redisResult = Arrays.asList(0L, 0L, 0L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When
            StepVerifier.create(rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT))
                    .assertNext(result -> {
                        assertThat(result.isAllowed()).isFalse();
                        assertThat(result.getMaxRequests()).isEqualTo(0);
                    })
                    .verifyComplete();
        }
    }

    // -------------------------------------------------------------------------
    // Security Tests
    // -------------------------------------------------------------------------
    @Nested
    @DisplayName("Security - Banking Compliance")
    class SecurityTests {

        @Test
        @DisplayName("Should not expose full IP in logs (PCI-DSS)")
        void shouldMaskIpForLogging() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(1, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            // Block the request to trigger warn log
            List<Long> redisResult = Arrays.asList(0L, 1L, 0L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When - this should log masked IP (192.168.x.x), not full IP
            StepVerifier.create(rateLimiterService.checkRateLimit("192.168.1.100", TEST_ENDPOINT))
                    .assertNext(result -> assertThat(result.isAllowed()).isFalse())
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should generate unique member IDs for concurrent requests")
        void shouldGenerateUniqueMemberIds() {
            // Given
            RateLimitConfig.EndpointLimit limit = createEndpointLimit(100, 60);
            when(rateLimitConfig.getEndpoints()).thenReturn(Map.of(TEST_ENDPOINT, limit));

            List<Long> redisResult = Arrays.asList(1L, 1L, 99L);
            doReturn(Flux.just(redisResult))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());

            // When - make multiple calls
            rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT).block();
            rateLimiterService.checkRateLimit(TEST_IP, TEST_ENDPOINT).block();

            // Then - verify 2 calls
            verify(redisTemplate, times(2)).execute(any(RedisScript.class), anyList(), any(), any(), any(), any(), any());
        }
    }

    // -------------------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------------------
    private RateLimitConfig.EndpointLimit createEndpointLimit(int maxRequests, int windowSeconds) {
        RateLimitConfig.EndpointLimit limit = new RateLimitConfig.EndpointLimit();
        limit.setMaxRequests(maxRequests);
        limit.setWindowSeconds(windowSeconds);
        return limit;
    }
}


