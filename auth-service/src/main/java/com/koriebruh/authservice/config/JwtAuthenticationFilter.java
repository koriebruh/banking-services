package com.koriebruh.authservice.config;

import com.koriebruh.authservice.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Tidak ada token — pass through, Spring Security handle sendiri
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        String requestPath = exchange.getRequest().getPath().value();

        try {
            Claims claims = jwtUtil.extractAllClaims(token);
            String tokenType = claims.get("type", String.class);

            // ENFORCE TOKEN TYPE PER ENDPOINT
            if (!isTokenTypeAllowed(requestPath, tokenType)) {
                log.warn("Token type mismatch. path={}, tokenType={}", requestPath, tokenType);
                return rejectRequest(exchange, "Invalid token type for this endpoint");
            }

            String userId = claims.getSubject();
            List<?> rawRoles = claims.get("roles", List.class);

            List<SimpleGrantedAuthority> authorities = rawRoles == null
                    ? List.of()
                    : rawRoles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toString()))
                    .toList();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            log.debug("JWT authenticated. userId={}, path={}, tokenType={}", userId, requestPath, tokenType);

            // Inject ke ReactiveSecurityContext
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        } catch (ExpiredJwtException e) {
            log.warn("JWT expired. path={}", requestPath);
            return rejectRequest(exchange, "Token has expired");
        } catch (SignatureException e) {
            log.warn("JWT signature invalid. path={}", requestPath);
            return rejectRequest(exchange, "Invalid token signature");
        } catch (MalformedJwtException e) {
            log.warn("JWT malformed. path={}", requestPath);
            return rejectRequest(exchange, "Malformed token");
        } catch (Exception e) {
            log.warn("JWT validation failed. path={}, reason={}", requestPath, e.getMessage());
            return rejectRequest(exchange, "Token validation failed");
        }
    }

    /**
     * Token type enforcement per endpoint:
     * - /mfa/verify        → hanya mfaToken
     * - /mfa/setup/**      → accessToken (type = null)
     * - /auth/refresh      → refreshToken
     * - semua lainnya      → accessToken (type = null)
     */
    private boolean isTokenTypeAllowed(String path, String tokenType) {
        if (path.contains("/mfa/verify")) {
            return "mfa".equals(tokenType);
        }
        if (path.contains("/auth/refresh")) {
            return "refresh".equals(tokenType);
        }
        return tokenType == null;
    }

    private Mono<Void> rejectRequest(ServerWebExchange exchange, String reason) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        byte[] body = ("{\"success\":false,\"message\":\"" + reason + "\"}").getBytes();
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(body))
        );
    }
}
