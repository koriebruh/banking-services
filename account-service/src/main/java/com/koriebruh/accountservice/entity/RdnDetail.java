package com.koriebruh.accountservice.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Extended attributes specific to RDN (Rekening Dana Nasabah) accounts.
 * One-to-one relationship with Account entity.
 * <p>
 * RDN is a special account type for capital market investors in Indonesia,
 * linked to KSEI (Kustodian Sentral Efek Indonesia).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("rdn_detail")
public class RdnDetail {

    @Id
    private UUID id;

    /**
     * Reference to the parent Account
     */
    @Column("account_id")
    private UUID accountId;

    /**
     * Single Investor ID issued by KSEI.
     * Unique per investor, format: 15 characters alphanumeric.
     */
    @Column("sid")
    private String sid;

    @Column("securities_company")
    private String securitiesCompany;

    /**
     * Timestamp when the RDN was verified by the securities company.
     * NULL means pending verification.
     */
    @Column("verified_at")
    private Instant verifiedAt;


    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    /**
     * Check if the RDN is verified and can be used for capital market transactions
     */
    public boolean isVerified() {
        return verifiedAt != null;
    }
}

