package com.koriebruh.authservice.unit.util;

import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JwtUtil Unit Tests")
class JwtUtilTest {

    private JwtUtil jwtUtil;
    private User testUser;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();

        // Set values via reflection (simulating @Value injection)
        ReflectionTestUtils.setField(jwtUtil, "secret", "my-super-secret-key-for-jwt-signing-at-least-256-bits-long");
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", 900000L); // 15 minutes
        ReflectionTestUtils.setField(jwtUtil, "refreshTokenExpiration", 604800000L); // 7 days
        ReflectionTestUtils.setField(jwtUtil, "mfaTokenExpiration", 300000L); // 5 minutes

        // Create test user
        testUser = User.builder()
                .id(UUID.randomUUID())
                .userCode("USR-20260302-00001")
                .email("test@example.com")
                .fullName("Test User")
                .role(UserRole.CUSTOMER)
                .status(UserStatus.ACTIVE)
                .mfaEnabled(false)
                .build();
    }

    @Nested
    @DisplayName("Access Token Generation")
    class AccessTokenGeneration {

        @Test
        @DisplayName("Should generate valid access token with correct claims")
        void shouldGenerateValidAccessToken() {
            // When
            String token = jwtUtil.generateAccessToken(testUser);

            // Then
            assertThat(token).isNotNull().isNotBlank();

            Claims claims = jwtUtil.extractAllClaims(token);
            assertThat(claims.getSubject()).isEqualTo(testUser.getId().toString());
            assertThat(claims.getIssuer()).isEqualTo("auth-service");
            assertThat(claims.getAudience()).contains("banking-api");
            assertThat(claims.getId()).isNotNull();
            assertThat(claims.get("userCode", String.class)).isEqualTo(testUser.getUserCode());
            assertThat(claims.get("roles", List.class)).contains(UserRole.CUSTOMER.name());
        }

        @Test
        @DisplayName("Should generate access token with correct expiration")
        void shouldGenerateAccessTokenWithCorrectExpiration() {
            // When
            String token = jwtUtil.generateAccessToken(testUser);

            // Then
            Claims claims = jwtUtil.extractAllClaims(token);
            long expirationTime = claims.getExpiration().getTime() - claims.getIssuedAt().getTime();

            // Allow 1 second tolerance
            assertThat(expirationTime).isBetween(899000L, 901000L);
        }

        @Test
        @DisplayName("Should generate unique jti for each token")
        void shouldGenerateUniqueJtiForEachToken() {
            // When
            String token1 = jwtUtil.generateAccessToken(testUser);
            String token2 = jwtUtil.generateAccessToken(testUser);

            // Then
            Claims claims1 = jwtUtil.extractAllClaims(token1);
            Claims claims2 = jwtUtil.extractAllClaims(token2);
            assertThat(claims1.getId()).isNotEqualTo(claims2.getId());
        }
    }

    @Nested
    @DisplayName("Refresh Token Generation")
    class RefreshTokenGeneration {

        @Test
        @DisplayName("Should generate valid refresh token with type claim")
        void shouldGenerateValidRefreshToken() {
            // When
            String token = jwtUtil.generateRefreshToken(testUser);

            // Then
            assertThat(token).isNotNull().isNotBlank();

            Claims claims = jwtUtil.extractAllClaims(token);
            assertThat(claims.getSubject()).isEqualTo(testUser.getId().toString());
            assertThat(claims.get("type", String.class)).isEqualTo("refresh");
            assertThat(claims.getIssuer()).isEqualTo("auth-service");
        }

        @Test
        @DisplayName("Should generate refresh token with longer expiration than access token")
        void shouldGenerateRefreshTokenWithLongerExpiration() {
            // When
            String accessToken = jwtUtil.generateAccessToken(testUser);
            String refreshToken = jwtUtil.generateRefreshToken(testUser);

            // Then
            Claims accessClaims = jwtUtil.extractAllClaims(accessToken);
            Claims refreshClaims = jwtUtil.extractAllClaims(refreshToken);

            long accessExpiry = accessClaims.getExpiration().getTime() - accessClaims.getIssuedAt().getTime();
            long refreshExpiry = refreshClaims.getExpiration().getTime() - refreshClaims.getIssuedAt().getTime();

            assertThat(refreshExpiry).isGreaterThan(accessExpiry);
        }
    }

    @Nested
    @DisplayName("MFA Token Generation")
    class MfaTokenGeneration {

        @Test
        @DisplayName("Should generate valid MFA token with mfa type claim")
        void shouldGenerateValidMfaToken() {
            // When
            String token = jwtUtil.generateMfaToken(testUser);

            // Then
            assertThat(token).isNotNull().isNotBlank();

            Claims claims = jwtUtil.extractAllClaims(token);
            assertThat(claims.getSubject()).isEqualTo(testUser.getId().toString());
            assertThat(claims.get("type", String.class)).isEqualTo("mfa");
            assertThat(claims.getAudience()).contains("auth-service");
        }

        @Test
        @DisplayName("Should generate MFA token with short expiration")
        void shouldGenerateMfaTokenWithShortExpiration() {
            // When
            String token = jwtUtil.generateMfaToken(testUser);

            // Then
            Claims claims = jwtUtil.extractAllClaims(token);
            long expirationTime = claims.getExpiration().getTime() - claims.getIssuedAt().getTime();

            // 5 minutes with tolerance
            assertThat(expirationTime).isBetween(299000L, 301000L);
        }
    }

    @Nested
    @DisplayName("Token Extraction")
    class TokenExtraction {

        @Test
        @DisplayName("Should extract userId from token")
        void shouldExtractUserIdFromToken() {
            // Given
            String token = jwtUtil.generateAccessToken(testUser);

            // When
            String userId = jwtUtil.extractUserId(token);

            // Then
            assertThat(userId).isEqualTo(testUser.getId().toString());
        }

        @Test
        @DisplayName("Should extract all claims from token")
        void shouldExtractAllClaimsFromToken() {
            // Given
            String token = jwtUtil.generateAccessToken(testUser);

            // When
            Claims claims = jwtUtil.extractAllClaims(token);

            // Then
            assertThat(claims).isNotNull();
            assertThat(claims.getSubject()).isEqualTo(testUser.getId().toString());
            assertThat(claims.getExpiration()).isNotNull();
            assertThat(claims.getIssuedAt()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Token Validation")
    class TokenValidation {

        @Test
        @DisplayName("Should return true for valid token with matching userId")
        void shouldReturnTrueForValidToken() {
            // Given
            String token = jwtUtil.generateAccessToken(testUser);

            // When
            boolean isValid = jwtUtil.isTokenValid(token, testUser.getId().toString());

            // Then
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false for valid token with wrong userId")
        void shouldReturnFalseForWrongUserId() {
            // Given
            String token = jwtUtil.generateAccessToken(testUser);
            String wrongUserId = UUID.randomUUID().toString();

            // When
            boolean isValid = jwtUtil.isTokenValid(token, wrongUserId);

            // Then
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for malformed token")
        void shouldReturnFalseForMalformedToken() {
            // When
            boolean isValid = jwtUtil.isTokenValid("malformed.token.here", testUser.getId().toString());

            // Then
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when parsing expired token")
        void shouldThrowExceptionForExpiredToken() {
            // Given - create JwtUtil with very short expiration
            JwtUtil shortExpiryJwtUtil = new JwtUtil();
            ReflectionTestUtils.setField(shortExpiryJwtUtil, "secret", "my-super-secret-key-for-jwt-signing-at-least-256-bits-long");
            ReflectionTestUtils.setField(shortExpiryJwtUtil, "accessTokenExpiration", 1L); // 1ms
            ReflectionTestUtils.setField(shortExpiryJwtUtil, "refreshTokenExpiration", 1L);
            ReflectionTestUtils.setField(shortExpiryJwtUtil, "mfaTokenExpiration", 1L);

            String token = shortExpiryJwtUtil.generateAccessToken(testUser);

            // Wait for token to expire
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Then
            assertThatThrownBy(() -> shortExpiryJwtUtil.extractAllClaims(token))
                    .isInstanceOf(ExpiredJwtException.class);
        }
    }

    @Nested
    @DisplayName("Expiration Time Methods")
    class ExpirationTimeMethods {

        @Test
        @DisplayName("Should return access token expiration in seconds")
        void shouldReturnAccessTokenExpirationInSeconds() {
            // When
            long expirationInSeconds = jwtUtil.getAccessTokenExpirationInSeconds();

            // Then
            assertThat(expirationInSeconds).isEqualTo(900L); // 15 minutes in seconds
        }

        @Test
        @DisplayName("Should return refresh token expiration in seconds")
        void shouldReturnRefreshTokenExpirationInSeconds() {
            // When
            long expirationInSeconds = jwtUtil.getRefreshTokenExpirationInSeconds();

            // Then
            assertThat(expirationInSeconds).isEqualTo(604800L); // 7 days in seconds
        }

        @Test
        @DisplayName("Should return MFA token expiration in seconds")
        void shouldReturnMfaTokenExpirationInSeconds() {
            // When
            long expirationInSeconds = jwtUtil.getMfaTokenExpirationInSeconds();

            // Then
            assertThat(expirationInSeconds).isEqualTo(300L); // 5 minutes in seconds
        }
    }

    @Nested
    @DisplayName("Different User Roles")
    class DifferentUserRoles {

        @Test
        @DisplayName("Should include ADMIN role in token claims")
        void shouldIncludeAdminRoleInClaims() {
            // Given
            User adminUser = testUser.toBuilder().role(UserRole.ADMIN).build();

            // When
            String token = jwtUtil.generateAccessToken(adminUser);

            // Then
            Claims claims = jwtUtil.extractAllClaims(token);
            assertThat(claims.get("roles", List.class)).contains(UserRole.ADMIN.name());
        }

        @Test
        @DisplayName("Should include TELLER role in token claims")
        void shouldIncludeTellerRoleInClaims() {
            // Given
            User tellerUser = testUser.toBuilder().role(UserRole.TELLER).build();

            // When
            String token = jwtUtil.generateAccessToken(tellerUser);

            // Then
            Claims claims = jwtUtil.extractAllClaims(token);
            assertThat(claims.get("roles", List.class)).contains(UserRole.TELLER.name());
        }
    }
}

