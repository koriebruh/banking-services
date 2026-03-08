package com.koriebruh.accountservice.entity;

import com.koriebruh.accountservice.entity.enums.InterestPayoutType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

/**
 * Extended attributes specific to DEPOSIT accounts (Time Deposit / Deposito).
 * One-to-one relationship with Account entity.
 * <p>
 * Banking Best Practices Applied:
 * - BigDecimal for principal and interest rate
 * - LocalDate for maturity (date only, no timezone needed)
 * - Validated tenor values (1, 3, 6, 12, 24 months)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("deposit_detail")
public class DepositDetail {

    @Id
    private UUID id;

    /**
     * Reference to the parent Account
     */
    @Column("account_id")
    private UUID accountId;

    /**
     * Initial locked amount at account opening.
     * NUMERIC(19,4) - prevents floating-point errors.
     */
    @Column("principal_amount")
    private BigDecimal principalAmount;

    /**
     * Annual interest rate as percentage (e.g., 5.25 = 5.25% p.a.)
     * NUMERIC(5,2) - supports up to 999.99%
     */
    @Column("interest_rate")
    private BigDecimal interestRate;

    /**
     * Deposit term in months.
     * Valid values: 1, 3, 6, 12, 24
     */
    @Column("tenor_months")
    private Short tenorMonths;

    /**
     * Date when deposit matures.
     * Calculated at opening: created_at + tenor_months
     */
    @Column("maturity_date")
    private LocalDate maturityDate;

    /**
     * Interest disbursement schedule
     */
    @Column("interest_payout")
    private InterestPayoutType interestPayout;

    /**
     * If true, deposit renews automatically at maturity
     */
    @Column("auto_rollover")
    private Boolean autoRollover;

    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    /**
     * Calculate expected interest at maturity
     */
    public BigDecimal calculateExpectedInterest() {
        if (principalAmount == null || interestRate == null || tenorMonths == null) {
            return BigDecimal.ZERO;
        }
        // Simple interest: P * R * T / 100 / 12
        return principalAmount
                .multiply(interestRate)
                .multiply(BigDecimal.valueOf(tenorMonths))
                .divide(BigDecimal.valueOf(1200), 4, java.math.RoundingMode.HALF_UP);
    }

    /**
     * Check if deposit has matured
     */
    public boolean isMatured() {
        return maturityDate != null && !LocalDate.now().isBefore(maturityDate);
    }
}

