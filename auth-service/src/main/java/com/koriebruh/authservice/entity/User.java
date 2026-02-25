package com.koriebruh.authservice.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.data.annotation.Id;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("users")
public class User {
    @Id
    private UUID id;

    @Column("user_code")
    private String userCode;

    @Column("full_name")
    private String fullName;

    @Column("email")
    private String email;

    @Column("phone_number")
    private String phoneNumber;

    @Column("password_hash")
    private String passwordHash;

    @Column("nik")
    private String nik;

    @Column("address")
    private String address;

    @Column("date_of_birth")
    private LocalDate dateOfBirth;

    @Column("role")
    private UserRole role;

    @Column("status")
    private UserStatus status;

    @Column("email_verified")
    private Boolean emailVerified;

    @Column("failed_login")
    private Short failedLogin;

    @Column("locked_until")
    private Instant  lockedUntil;

    @Column("last_login_at")
    private Instant  lastLoginAt;

    @CreatedDate
    @Column("created_at")
    private Instant  createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant  updatedAt;

    @Column("deleted_at")
    private Instant deletedAt;
}

