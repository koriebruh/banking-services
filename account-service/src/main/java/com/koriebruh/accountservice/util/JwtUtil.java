package com.koriebruh.accountservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;


/**
 * JWT utility for account-service.
 *
 * <p>This service does NOT issue tokens — that is the sole responsibility of auth-service.
 * This utility only verifies token signatures and extracts claims from tokens
 * issued by auth-service.
 *
 * <p>Verification uses the RSA public key loaded from a PEM file.
 * The private key is never accessible to this service — even if this service
 * is compromised, tokens cannot be forged.
 *
 * <p><b>Flow:</b>
 * <pre>
 *   Client → Authorization: Bearer {token}
 *     → JwtAuthenticationFilter
 *       → isAccessTokenValid()  — verify signature + expiry + type
 *       → extractUserId()       — inject into ReactiveSecurityContext
 *       → extractRoles()        — build GrantedAuthority list
 * </pre>
 */
@Component
public class JwtUtil {

    @Value("${app.jwt.public-key}")
    private Resource publicKeyResource;

    private PublicKey cachedPublicKey;

    // -------------------------------------------------------------------------
    // Key
    // -------------------------------------------------------------------------

    /**
     * Parses the RSA public key from PEM file.
     * Result is cached after first load — key is immutable and safe to reuse.
     *
     * <p>This key is identical to the one distributed from auth-service.
     * It is used only for signature verification, never for signing.
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
     * Reads content from a Spring Resource (classpath or file path).
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
    // Parse
    // -------------------------------------------------------------------------

    /**
     * Parses and returns all claims from the token.
     * Verifies the RSA signature using the public key.
     * Throws JwtException if the signature is invalid or the token is expired.
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

    // -------------------------------------------------------------------------
    // Extract
    // -------------------------------------------------------------------------

    /**
     * Extracts the user ID (subject) from the token.
     *
     * @param token raw JWT string
     * @return userId as UUID
     */
    public UUID extractUserId(String token) {
        return UUID.fromString(extractAllClaims(token).getSubject());
    }

    /**
     * Extracts the roles claim from the token.
     * Embedded by auth-service as a list, e.g. ["CUSTOMER"] or ["ADMIN"] or ["TELLER"].
     *
     * @param token raw JWT string
     * @return list of role strings
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }

    /**
     * Extracts the userCode business identifier from the token.
     * e.g. USR-20260308-00001 — non-PII, safe to log.
     *
     * @param token raw JWT string
     * @return userCode string
     */
    public String extractUserCode(String token) {
        return extractAllClaims(token).get("userCode", String.class);
    }

    /**
     * Extracts the token type claim.
     * Access tokens carry no "type" claim (returns null).
     * Refresh tokens carry type = "refresh".
     * MFA tokens carry type = "mfa".
     *
     * @param token raw JWT string
     * @return token type string, or null if access token
     */
    public String extractTokenType(String token) {
        return extractAllClaims(token).get("type", String.class);
    }

    // -------------------------------------------------------------------------
    // Validate
    // -------------------------------------------------------------------------

    /**
     * Returns true if the token is a valid access token:
     * — RSA signature verified against public key
     * — Token is not expired
     * — Token type is "access" (rejects refresh/mfa tokens)
     *
     * <p><b>Flow:</b>    JwtAuthenticationFilter → isAccessTokenValid → inject SecurityContext
     * <p><b>Security:</b> Rejects refresh and MFA tokens that are mistakenly sent to this service.
     *
     * @param token raw JWT string
     * @return true if valid access token
     */
    public boolean isAccessTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            boolean notExpired = claims.getExpiration().after(new Date());
            String tokenType = claims.get("type", String.class);
            boolean isAccessToken = "access".equals(tokenType);
            return isAccessToken && notExpired;
        } catch (Exception e) {
            return false;
        }
    }
}