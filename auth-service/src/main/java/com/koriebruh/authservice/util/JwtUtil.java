package com.koriebruh.authservice.util;

import com.koriebruh.authservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * JWT utility for auth-service.
 *
 * <p>Uses RSA-256 (asymmetric):
 * <ul>
 *   <li><b>Private key</b> — held only by auth-service, used to sign tokens.</li>
 *   <li><b>Public key</b>  — distributed to all downstream services, used to verify tokens.</li>
 * </ul>
 *
 * <p>This design ensures that even if a downstream service (account-service,
 * transfer-service, etc.) is compromised, it cannot forge tokens — it only
 * holds the public key and cannot sign.
 *
 * <p><b>Token types issued:</b>
 * <ul>
 *   <li><b>Access token</b>  — 15 min, no "type" claim, used for API requests.</li>
 *   <li><b>Refresh token</b> — 7 days, type = "refresh", stored hashed in DB.</li>
 *   <li><b>MFA token</b>     — 5 min, type = "mfa", used only during MFA step.</li>
 * </ul>
 *
 * <p><b>Claims in access token:</b> sub (userId), roles, userCode, jti, iss, aud, iat, exp.
 * No sensitive data (email, password, status) is ever embedded.
 */
@Component
public class JwtUtil {

    @Value("${app.jwt.private-key}")
    private Resource privateKeyResource;

    @Value("${app.jwt.public-key}")
    private Resource publicKeyResource;

    @Value("${app.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${app.jwt.mfa-token-expiration}")
    private long mfaTokenExpiration;

    private PrivateKey cachedPrivateKey;
    private PublicKey cachedPublicKey;

    // -------------------------------------------------------------------------
    // Keys
    // -------------------------------------------------------------------------

    /**
     * Parses RSA private key from PEM file (PKCS#8 format).
     * Used exclusively for signing — never shared outside auth-service.
     */
    private PrivateKey getPrivateKey() {
        if (cachedPrivateKey != null) {
            return cachedPrivateKey;
        }
        try {
            String pem = readResource(privateKeyResource);
            String cleaned = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(cleaned);
            cachedPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
            return cachedPrivateKey;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA private key", e);
        }
    }

    /**
     * Parses RSA public key from PEM file.
     * Used for verifying tokens issued by this service.
     * This same key is distributed to all downstream services.
     */
    private PublicKey getPublicKey() {
        if (cachedPublicKey != null) {
            return cachedPublicKey;
        }
        try {
            String pem = readResource(publicKeyResource);
            String cleaned = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(cleaned);
            cachedPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
            return cachedPublicKey;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA public key", e);
        }
    }

    /**
     * Reads content from a Spring Resource (classpath, file, etc.)
     */
    private String readResource(Resource resource) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read resource: " + resource, e);
        }
    }

    // -------------------------------------------------------------------------
    // Generate
    // -------------------------------------------------------------------------

    /**
     * Issues a signed JWT access token for the authenticated user.
     *
     * <p><b>Flow:</b> login / mfa-validate → generateAccessToken → returned to client.
     *
     * <p><b>Security:</b> Short-lived (15 min). No sensitive data embedded.
     * Downstream services verify this token using the public key only.
     *
     * @param user authenticated user entity
     * @return signed JWT access token
     */
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", List.of(user.getRole().name()));
        claims.put("userCode", user.getUserCode());

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer("auth-service")
                .audience().add("banking-api").and()
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Issues a signed JWT refresh token.
     *
     * <p><b>Flow:</b> login → generateRefreshToken → stored hashed in DB → returned to client.
     * Used only at POST /auth/refresh to obtain a new access token.
     *
     * <p><b>Security:</b> type = "refresh" prevents this token from being accepted
     * as an access token in downstream services.
     *
     * @param user authenticated user entity
     * @return signed JWT refresh token
     */
    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer("auth-service")
                .audience().add("banking-api").and()
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Issues a short-lived MFA token after successful password verification.
     *
     * <p><b>Flow:</b> login (MFA enabled) → generateMfaToken → client sends to
     * POST /auth/mfa/validate with TOTP code → exchange for full token pair.
     *
     * <p><b>Security:</b> aud = "auth-service" ensures this token is rejected
     * by all downstream services. type = "mfa" adds a second layer of enforcement.
     *
     * @param user authenticated user entity
     * @return signed JWT MFA token
     */
    public String generateMfaToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "mfa");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer("auth-service")
                .audience().add("auth-service").and()
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + mfaTokenExpiration))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    // -------------------------------------------------------------------------
    // Parse
    // -------------------------------------------------------------------------

    /**
     * Parses and returns all claims from a token.
     * Verifies signature using the public key.
     * Throws JwtException if signature is invalid or token is expired.
     *
     * @param token raw JWT string (without "Bearer " prefix)
     * @return parsed Claims
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts the subject (userId) from a token.
     *
     * @param token raw JWT string
     * @return userId as String
     */
    public String extractUserId(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extracts the token type claim.
     * Returns null for access tokens, "refresh" or "mfa" otherwise.
     *
     * @param token raw JWT string
     * @return token type or null
     */
    public String extractTokenType(String token) {
        return extractAllClaims(token).get("type", String.class);
    }

    // -------------------------------------------------------------------------
    // Validate
    // -------------------------------------------------------------------------

    /**
     * Returns true if the token signature is valid and not expired.
     *
     * @param token  raw JWT string
     * @param userId expected subject
     * @return true if valid
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

    // -------------------------------------------------------------------------
    // Expiration helpers
    // -------------------------------------------------------------------------

    public long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration / 1000;
    }

    public long getRefreshTokenExpirationInSeconds() {
        return refreshTokenExpiration / 1000;
    }

    public long getMfaTokenExpirationInSeconds() {
        return mfaTokenExpiration / 1000;
    }
}