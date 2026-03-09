package com.koriebruh.accountservice.filter;

import com.koriebruh.accountservice.util.JwtUtil;
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

/**
 * JWT authentication filter for account-service.
 *
 * <p>Validates incoming access tokens on every protected request.
 * Token verification uses the RSA public key — this service cannot issue tokens.
 *
 * <p><b>Flow:</b>
 * <pre>
 *   Request → extract Bearer token
 *     → isAccessTokenValid() — verify RSA signature + expiry + type
 *     → extract userId + roles
 *     → inject UsernamePasswordAuthenticationToken into ReactiveSecurityContext
 *     → chain.filter()
 * </pre>
 *
 * <p><b>Security:</b>
 * <ul>
 *   <li>Refresh tokens (type = "refresh") are explicitly rejected — they must never
 *       reach account-service endpoints.</li>
 *   <li>MFA tokens (type = "mfa") are explicitly rejected — they are only valid
 *       inside auth-service.</li>
 *   <li>No token → pass through to Spring Security, which handles 401 for protected routes.</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String requestPath = exchange.getRequest().getPath().value();

        // No token — pass through, Spring Security handles 401 for protected routes
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            // Validates: RSA signature + expiry + must be access token (type = null)
            if (!jwtUtil.isAccessTokenValid(token)) {
                log.warn("Invalid or non-access token received. path={}", requestPath);
                return rejectRequest(exchange, "Invalid token type for this endpoint");
            }

            String userId = jwtUtil.extractUserId(token).toString();
            List<String> roles = jwtUtil.extractRoles(token);
            String userCode = jwtUtil.extractUserCode(token);

            List<SimpleGrantedAuthority> authorities = roles == null
                    ? List.of()
                    : roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            log.debug("JWT authenticated. userId={}, userCode={}, path={}", userId, userCode, requestPath);

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

    private Mono<Void> rejectRequest(ServerWebExchange exchange, String reason) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        byte[] body = ("{\"success\":false,\"message\":\"" + reason + "\"}").getBytes();
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(body))
        );
    }
}