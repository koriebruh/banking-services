package com.koriebruh.authservice.repository;

import com.koriebruh.authservice.entity.User;

import com.koriebruh.authservice.entity.UserRole;
import com.koriebruh.authservice.entity.UserStatus;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface UserRepository extends ReactiveCrudRepository<User, UUID> {
    Mono<User> findByEmail(String email);

    Mono<User> findByUserCode(String userCode);

    Mono<User> findByPhoneNumber(String phoneNumber);

    Mono<User> findByNik(String nik);

    Mono<Boolean> existsByEmail(String email);

    Mono<Boolean> existsByUserCode(String userCode);

    Mono<Boolean> existsByPhoneNumber(String phoneNumber);

    Mono<Boolean> existsByNik(String nik);

    Flux<User> findByRole(UserRole role);

    Flux<User> findByStatus(UserStatus status);

    Flux<User> findByRoleAndStatus(UserRole role, UserStatus status);

    @Query("SELECT * FROM users WHERE email = :email AND deleted_at IS NULL")
    Mono<User> findActiveUserByEmail(@Param("email") String email);

    @Query("SELECT * FROM users WHERE locked_until IS NOT NULL AND locked_until > :now")
    Flux<User> findLockedUsers(@Param("now") Instant now);

    @Modifying
    @Query("UPDATE users SET failed_login = :failedLogin, updated_at = :now WHERE id = :userId")
    Mono<Void> updateFailedLoginAttempts(@Param("userId") UUID userId,
                                         @Param("failedLogin") Short failedLogin,
                                         @Param("now") Instant now);

    @Modifying
    @Query("UPDATE users SET locked_until = :lockedUntil, updated_at = :now WHERE id = :userId")
    Mono<Void> lockUser(@Param("userId") UUID userId,
                        @Param("lockedUntil") Instant lockedUntil,
                        @Param("now") Instant now);

    @Modifying
    @Query("UPDATE users SET failed_login = 0, locked_until = NULL, last_login_at = :now, updated_at = :now WHERE id = :userId")
    Mono<Void> updateSuccessfulLogin(@Param("userId") UUID userId,
                                     @Param("now") Instant now);

    @Modifying
    @Query("UPDATE users SET email_verified = true, status = 'ACTIVE', updated_at = :now WHERE id = :userId")
    Mono<Void> verifyUserEmail(@Param("userId") UUID userId,
                               @Param("now") Instant now);

    @Modifying
    @Query("UPDATE users SET status = :status, updated_at = :now WHERE id = :userId")
    Mono<Void> updateUserStatus(@Param("userId") UUID userId,
                                @Param("status") String status,
                                @Param("now") Instant now);

    @Modifying
    @Query("UPDATE users SET password_hash = :passwordHash, updated_at = :now WHERE id = :userId")
    Mono<Void> updatePassword(@Param("userId") UUID userId,
                              @Param("passwordHash") String passwordHash,
                              @Param("now") Instant now);

    @Query("SELECT nextval('user_code_seq')")
    Mono<Long> getNextSequence();

}

