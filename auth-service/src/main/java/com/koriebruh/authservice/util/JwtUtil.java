package com.koriebruh.authservice.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for generating and validating JWT access tokens.
 * Uses HMAC-SHA256 algorithm with a secret key from application properties.
 */
@Component
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    // ── Key ──────────────────────────────────────────────────────────────────

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // ── Generate ─────────────────────────────────────────────────────────────

    /**
     * Generates a signed JWT access token for the given user.
     *
     * @param email    subject claim (user email)
     * @param role     user role embedded as a custom claim
     * @param userCode user business code (e.g. USR-20240315-0001)
     * @return signed JWT string
     */
    public String generateAccessToken(String email, String role, String userCode) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);
        claims.put("userCode", userCode);

        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    // ── Parse ─────────────────────────────────────────────────────────────────

    /**
     * Extracts all claims from a JWT token.
     *
     * @param token JWT string
     * @return parsed Claims object
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts the subject (email) from a JWT token.
     */
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extracts the user role claim from a JWT token.
     */
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    // ── Validate ─────────────────────────────────────────────────────────────

    /**
     * Returns true if the token is valid (signature OK and not expired).
     */
    public boolean isTokenValid(String token, String email) {
        try {
            return extractEmail(token).equals(email) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    /**
     * Returns the access token expiration time in seconds.
     */
    public long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration / 1000;
    }
}