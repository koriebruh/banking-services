package com.koriebruh.accountservice.filter;

import com.koriebruh.accountservice.dto.ApiResponse;
import com.koriebruh.accountservice.dto.ApiResponseFactory;
import com.koriebruh.accountservice.filter.CorrelationIdFilter;
import com.koriebruh.accountservice.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtUtil jwtUtil;

    private final ApiResponseFactory apiResponseFactory;

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        String requestPath = exchange.getRequest().getPath().value();

        try {
            // Account-service hanya menerima access token, tolak yang lain
            if (!jwtUtil.isAccessTokenValid(token)) {
                String y = jwtUtil.extractTokenType(token);
                log.warn("[JwtAuthFilter] Invalid or non-access token. path={} and that is token={}", requestPath, y);
                return rejectRequest(exchange, "Invalid access token");
            }

            Claims claims = jwtUtil.extractAllClaims(token);

            String userId = claims.getSubject();
            List<?> rawRoles = claims.get("roles", List.class);

            List<SimpleGrantedAuthority> authorities = rawRoles == null
                    ? List.of()
                    : rawRoles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toString()))
                    .toList();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            log.debug("[JwtAuthFilter] Authenticated. userId={}, path={}", userId, requestPath);

            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        } catch (ExpiredJwtException e) {
            log.warn("[JwtAuthFilter] Token expired. path={}", requestPath);
            return rejectRequest(exchange, "Token has expired");
        } catch (SignatureException e) {
            log.warn("[JwtAuthFilter] Invalid signature. path={}", requestPath);
            return rejectRequest(exchange, "Invalid token signature");
        } catch (MalformedJwtException e) {
            log.warn("[JwtAuthFilter] Malformed token. path={}", requestPath);
            return rejectRequest(exchange, "Malformed token");
        } catch (Exception e) {
            log.warn("[JwtAuthFilter] Validation failed. path={}, reason={}", requestPath, e.getMessage());
            return rejectRequest(exchange, "Token validation failed");
        }
    }


    /**
     * Writes a structured 401 Unauthorized JSON response using {@link ApiResponseFactory}.
     * Correlation ID is sourced from Reactor Context (injected by CorrelationIdFilter).
     * Falls back to null if not present (e.g., if filter order is misconfigured).
     */
    private Mono<Void> rejectRequest(ServerWebExchange exchange, String message) {
        String correlationId = exchange.getRequest()
                .getHeaders()
                .getFirst(CorrelationIdFilter.CORRELATION_ID_HEADER);
        try {
            ApiResponse<Void> body = apiResponseFactory.error(message, correlationId);
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("[JwtAuthFilter] Failed to serialize error response", e);
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }

    }
}