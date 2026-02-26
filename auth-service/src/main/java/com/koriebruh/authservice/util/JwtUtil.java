package com.koriebruh.authservice.util;


import com.koriebruh.authservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

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

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${app.jwt.mfa-token-expiration}")
    private long mfaTokenExpiration;

    // ── Key ──────────────────────────────────────────────────────────────────

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // ── Generate ─────────────────────────────────────────────────────────────

    /**
     * Generates a signed JWT access token for the given authenticated user.
     *
     * Token Characteristics:
     * - Subject (sub)        : Immutable internal user ID (UUID)
     * - Roles (custom claim) : Used for authorization in downstream services
     * - userCode             : Business identifier (non-PII reference)
     * - jti                  : Unique token identifier (supports revocation tracking)
     * - iss                  : Token issuer (auth-service)
     * - aud                  : Intended audience (e.g. banking-api)
     * - iat / exp            : Issued time and expiration (short-lived)
     *
     * IMPORTANT:
     * - No sensitive or mutable data (email, password, NIK, status) is embedded.
     * - Access tokens are short-lived and stateless.
     *
     * @param user authenticated user entity
     * @return signed JWT access token string
     */
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", List.of(user.getRole().name()));
        claims.put("userCode", user.getUserCode());


        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer("auth-service")
                .audience().add("banking-api").and()
                .id(jti)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Generates a signed JWT refresh token.
     *
     * Characteristics:
     * - Subject (sub) : Immutable user ID
     * - Type          : "refresh" (token differentiation)
     * - jti           : Unique token identifier
     * - Longer expiry compared to access token
     *
     * NOTE:
     * - Must be stored in DB (hashed recommended).
     * - Used to obtain new access tokens.
     *
     * @param user authenticated user
     * @return signed JWT refresh token string
     */
    public String generateRefreshToken(User user) {

        String jti = UUID.randomUUID().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer("auth-service")
                .audience().add("banking-api").and()
                .id(jti)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getSigningKey())
                .compact();
    }


    public String generateMfaToken(User user) {

        String jti = UUID.randomUUID().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "mfa");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer("auth-service")
                .audience().add("auth-service").and()
                .id(jti)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + mfaTokenExpiration))
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
     * Extracts the subject (userId) from a JWT token.
     */
    public String extractUserId(String token) {
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
    public boolean isTokenValid(String token, String userId) {
        try {
            return extractUserId(token).equals(userId) && !isTokenExpired(token);
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

    public long getRefreshTokenExpirationInSeconds() {
        return refreshTokenExpiration  / 1000;
    }

    public long getMfaTokenExpirationInSeconds() {
        return mfaTokenExpiration  / 1000;
    }
}