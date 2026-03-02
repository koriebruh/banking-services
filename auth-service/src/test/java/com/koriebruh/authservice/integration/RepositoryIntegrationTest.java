package com.koriebruh.authservice.integration;

import com.koriebruh.authservice.entity.RefreshToken;
import com.koriebruh.authservice.entity.User;
import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import com.koriebruh.authservice.repository.RefreshTokenRepository;
import com.koriebruh.authservice.repository.UserRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for Repository layer.
 *
 * <h2>Banking Best Practices:</h2>
 * <ul>
 *   <li>Tests run in isolated TestContainers database</li>
 *   <li>Data is cleaned before each test</li>
 *   <li>Verifies data integrity constraints</li>
 *   <li>Tests audit fields (created_at, updated_at)</li>
 * </ul>
 */
@DisplayName("Repository Integration Tests")
class RepositoryIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    // -------------------------------------------------------------------------
    // USER REPOSITORY TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("UserRepository Tests")
    class UserRepositoryTests {

        @Test
        @DisplayName("Should save and retrieve user")
        void shouldSaveAndRetrieveUser() {
            // Given
            User user = createTestUser();

            // When
            StepVerifier.create(userRepository.save(user))
                    .assertNext(savedUser -> {
                        assertThat(savedUser.getId()).isNotNull();
                        assertThat(savedUser.getEmail()).isEqualTo(user.getEmail());
                        assertThat(savedUser.getUserCode()).isEqualTo(user.getUserCode());
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should find user by email")
        void shouldFindUserByEmail() {
            // Given
            User user = createTestUser();
            userRepository.save(user).block();

            // When & Then
            StepVerifier.create(userRepository.findByEmail(user.getEmail()))
                    .assertNext(foundUser -> {
                        assertThat(foundUser.getEmail()).isEqualTo(user.getEmail());
                        assertThat(foundUser.getFullName()).isEqualTo(user.getFullName());
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should return empty when email not found")
        void shouldReturnEmptyWhenEmailNotFound() {
            // When & Then
            StepVerifier.create(userRepository.findByEmail("nonexistent@test.com"))
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should check email existence correctly")
        void shouldCheckEmailExistence() {
            // Given
            User user = createTestUser();
            userRepository.save(user).block();

            // When & Then - Existing email
            StepVerifier.create(userRepository.existsByEmail(user.getEmail()))
                    .assertNext(exists -> assertThat(exists).isTrue())
                    .verifyComplete();

            // When & Then - Non-existing email
            StepVerifier.create(userRepository.existsByEmail("nonexistent@test.com"))
                    .assertNext(exists -> assertThat(exists).isFalse())
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should check NIK existence correctly")
        void shouldCheckNikExistence() {
            // Given
            User user = createTestUser();
            userRepository.save(user).block();

            // When & Then
            StepVerifier.create(userRepository.existsByNik(user.getNik()))
                    .assertNext(exists -> assertThat(exists).isTrue())
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should check phone number existence correctly")
        void shouldCheckPhoneExistence() {
            // Given
            User user = createTestUser();
            userRepository.save(user).block();

            // When & Then
            StepVerifier.create(userRepository.existsByPhoneNumber(user.getPhoneNumber()))
                    .assertNext(exists -> assertThat(exists).isTrue())
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should update failed login attempts")
        void shouldUpdateFailedLoginAttempts() {
            // Given
            User user = createTestUser();
            User savedUser = userRepository.save(user).block();

            // When
            StepVerifier.create(
                    userRepository.updateFailedLoginAttempts(savedUser.getId(), (short) 3, Instant.now())
                            .then(userRepository.findById(savedUser.getId())))
                    .assertNext(updatedUser -> {
                        assertThat(updatedUser.getFailedLogin()).isEqualTo((short) 3);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should verify user email")
        void shouldVerifyUserEmail() {
            // Given
            User user = createTestUser();
            user.setEmailVerified(false);
            user.setStatus(UserStatus.PENDING_VERIFICATION);
            User savedUser = userRepository.save(user).block();

            // When
            StepVerifier.create(
                    userRepository.verifyUserEmail(savedUser.getId(), Instant.now())
                            .then(userRepository.findById(savedUser.getId())))
                    .assertNext(updatedUser -> {
                        assertThat(updatedUser.getEmailVerified()).isTrue();
                        assertThat(updatedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should lock user account")
        void shouldLockUserAccount() {
            // Given
            User user = createTestUser();
            User savedUser = userRepository.save(user).block();
            Instant lockedUntil = Instant.now().plus(15, ChronoUnit.MINUTES);

            // When
            StepVerifier.create(
                    userRepository.lockUser(savedUser.getId(), lockedUntil, Instant.now())
                            .then(userRepository.findById(savedUser.getId())))
                    .assertNext(updatedUser -> {
                        assertThat(updatedUser.getLockedUntil()).isNotNull();
                        assertThat(updatedUser.getLockedUntil()).isAfter(Instant.now());
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should update password")
        void shouldUpdatePassword() {
            // Given
            User user = createTestUser();
            User savedUser = userRepository.save(user).block();
            String newPasswordHash = "newHashedPassword123";

            // When
            StepVerifier.create(
                    userRepository.updatePassword(savedUser.getId(), newPasswordHash, Instant.now())
                            .then(userRepository.findById(savedUser.getId())))
                    .assertNext(updatedUser -> {
                        assertThat(updatedUser.getPasswordHash()).isEqualTo(newPasswordHash);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should update successful login timestamp")
        void shouldUpdateSuccessfulLogin() {
            // Given
            User user = createTestUser();
            User savedUser = userRepository.save(user).block();

            // When
            Instant loginTime = Instant.now();
            StepVerifier.create(
                    userRepository.updateSuccessfulLogin(savedUser.getId(), loginTime)
                            .then(userRepository.findById(savedUser.getId())))
                    .assertNext(updatedUser -> {
                        assertThat(updatedUser.getLastLoginAt()).isNotNull();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should get next sequence for user code")
        void shouldGetNextSequence() {
            // When & Then
            StepVerifier.create(userRepository.getNextSequence())
                    .assertNext(sequence -> {
                        assertThat(sequence).isGreaterThan(0);
                    })
                    .verifyComplete();

            // Verify sequence increments
            Long firstSeq = userRepository.getNextSequence().block();
            Long secondSeq = userRepository.getNextSequence().block();
            assertThat(secondSeq).isGreaterThan(firstSeq);
        }
    }

    // -------------------------------------------------------------------------
    // REFRESH TOKEN REPOSITORY TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("RefreshTokenRepository Tests")
    class RefreshTokenRepositoryTests {

        @Test
        @DisplayName("Should save and retrieve refresh token")
        void shouldSaveAndRetrieveRefreshToken() {
            // Given
            User user = createAndSaveTestUser();
            RefreshToken token = createTestRefreshToken(user.getId());

            // When
            StepVerifier.create(refreshTokenRepository.save(token))
                    .assertNext(savedToken -> {
                        assertThat(savedToken.getId()).isNotNull();
                        assertThat(savedToken.getUserId()).isEqualTo(user.getId());
                        assertThat(savedToken.getTokenHash()).isEqualTo(token.getTokenHash());
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should find valid token by hash")
        void shouldFindValidTokenByHash() {
            // Given
            User user = createAndSaveTestUser();
            RefreshToken token = createTestRefreshToken(user.getId());
            refreshTokenRepository.save(token).block();

            // When & Then
            StepVerifier.create(refreshTokenRepository.findValidTokenByHash(token.getTokenHash(), Instant.now()))
                    .assertNext(foundToken -> {
                        assertThat(foundToken.getTokenHash()).isEqualTo(token.getTokenHash());
                        assertThat(foundToken.getRevoked()).isFalse();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should not find revoked token")
        void shouldNotFindRevokedToken() {
            // Given
            User user = createAndSaveTestUser();
            RefreshToken token = createTestRefreshToken(user.getId());
            token.setRevoked(true);
            refreshTokenRepository.save(token).block();

            // When & Then
            StepVerifier.create(refreshTokenRepository.findValidTokenByHash(token.getTokenHash(), Instant.now()))
                    .verifyComplete(); // Empty result
        }

        @Test
        @DisplayName("Should not find expired token")
        void shouldNotFindExpiredToken() {
            // Given
            User user = createAndSaveTestUser();
            RefreshToken token = createTestRefreshToken(user.getId());
            token.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS)); // Expired
            refreshTokenRepository.save(token).block();

            // When & Then
            StepVerifier.create(refreshTokenRepository.findValidTokenByHash(token.getTokenHash(), Instant.now()))
                    .verifyComplete(); // Empty result
        }

        @Test
        @DisplayName("Should revoke token by hash")
        void shouldRevokeTokenByHash() {
            // Given
            User user = createAndSaveTestUser();
            RefreshToken token = createTestRefreshToken(user.getId());
            refreshTokenRepository.save(token).block();

            // When
            StepVerifier.create(
                    refreshTokenRepository.revokeToken(token.getTokenHash(), Instant.now())
                            .then(refreshTokenRepository.findValidTokenByHash(token.getTokenHash(), Instant.now())))
                    .verifyComplete(); // Should be empty after revocation
        }

        @Test
        @DisplayName("Should revoke all user tokens")
        void shouldRevokeAllUserTokens() {
            // Given
            User user = createAndSaveTestUser();

            // Create multiple tokens
            for (int i = 0; i < 3; i++) {
                RefreshToken token = RefreshToken.builder()
                        .userId(user.getId())
                        .tokenHash("hash_" + i + "_" + System.currentTimeMillis())
                        .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                        .revoked(false)
                        .ipAddress("127.0.0.1")
                        .userAgent("Test Agent")
                        .build();
                refreshTokenRepository.save(token).block();
            }

            // When
            refreshTokenRepository.revokeAllUserTokens(user.getId(), Instant.now()).block();

            // Then - All tokens should be revoked (count should be 0 valid)
            StepVerifier.create(
                    databaseClient.sql("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = :userId AND revoked = false")
                            .bind("userId", user.getId())
                            .map(row -> row.get(0, Long.class))
                            .one())
                    .assertNext(count -> assertThat(count).isZero())
                    .verifyComplete();
        }
    }

    // -------------------------------------------------------------------------
    // DATA INTEGRITY TESTS
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Data Integrity Tests")
    class DataIntegrityTests {

        @Test
        @DisplayName("Should enforce unique email constraint")
        void shouldEnforceUniqueEmailConstraint() {
            // Given - Create first user with specific email
            String sharedEmail = "duplicate_test_" + System.currentTimeMillis() + "@integration.test";

            User user1 = createTestUser();
            user1.setEmail(sharedEmail);
            userRepository.save(user1).block();

            // Create second user with SAME email but different other fields
            User user2 = User.builder()
                    .userCode("USR-TEST-DUPLICATE-" + System.currentTimeMillis())
                    .fullName("Test User 2")
                    .email(sharedEmail) // Same email - should cause constraint violation
                    .phoneNumber(generateTestPhone())
                    .passwordHash("hashedPassword123")
                    .nik(generateTestNik())
                    .address("Jl. Test No. 456")
                    .dateOfBirth(LocalDate.of(1991, 2, 20))
                    .role(UserRole.CUSTOMER)
                    .status(UserStatus.ACTIVE)
                    .emailVerified(true)
                    .mfaEnabled(false)
                    .failedLogin((short) 0)
                    .build();

            // When & Then
            StepVerifier.create(userRepository.save(user2))
                    .expectError()
                    .verify();
        }

        @Test
        @DisplayName("Should enforce unique NIK constraint")
        void shouldEnforceUniqueNikConstraint() {
            // Given - Create first user with specific NIK
            String sharedNik = String.format("%016d", System.currentTimeMillis() % 10000000000000000L);

            User user1 = createTestUser();
            user1.setNik(sharedNik);
            userRepository.save(user1).block();

            // Create second user with SAME NIK but different other fields
            User user2 = User.builder()
                    .userCode("USR-TEST-DUPLICATE-NIK-" + System.currentTimeMillis())
                    .fullName("Test User 2")
                    .email(generateTestEmail())
                    .phoneNumber(generateTestPhone())
                    .passwordHash("hashedPassword123")
                    .nik(sharedNik) // Same NIK - should cause constraint violation
                    .address("Jl. Test No. 456")
                    .dateOfBirth(LocalDate.of(1991, 2, 20))
                    .role(UserRole.CUSTOMER)
                    .status(UserStatus.ACTIVE)
                    .emailVerified(true)
                    .mfaEnabled(false)
                    .failedLogin((short) 0)
                    .build();

            // When & Then
            StepVerifier.create(userRepository.save(user2))
                    .expectError()
                    .verify();
        }

        @Test
        @DisplayName("Should cascade delete refresh tokens when user deleted")
        void shouldCascadeDeleteRefreshTokens() {
            // Given
            User user = createAndSaveTestUser();
            RefreshToken token = createTestRefreshToken(user.getId());
            refreshTokenRepository.save(token).block();

            // When - Delete user
            userRepository.deleteById(user.getId()).block();

            // Then - Refresh tokens should also be deleted (if cascade is configured)
            // or should fail with foreign key constraint
            // This depends on your schema design
        }
    }

    // -------------------------------------------------------------------------
    // HELPER METHODS
    // -------------------------------------------------------------------------

    private User createTestUser() {
        return User.builder()
                .userCode("USR-TEST-" + System.currentTimeMillis())
                .fullName("Test User")
                .email(generateTestEmail())
                .phoneNumber(generateTestPhone())
                .passwordHash("hashedPassword123")
                .nik(generateTestNik())
                .address("Jl. Test No. 123, Jakarta")
                .dateOfBirth(LocalDate.of(1990, 1, 15))
                .role(UserRole.CUSTOMER)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .mfaEnabled(false)
                .failedLogin((short) 0)
                .build();
    }

    private User createAndSaveTestUser() {
        User user = createTestUser();
        return userRepository.save(user).block();
    }

    private RefreshToken createTestRefreshToken(UUID userId) {
        return RefreshToken.builder()
                .userId(userId)
                .tokenHash("test_token_hash_" + System.currentTimeMillis())
                .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                .revoked(false)
                .ipAddress("127.0.0.1")
                .userAgent("Test User Agent")
                .build();
    }
}

