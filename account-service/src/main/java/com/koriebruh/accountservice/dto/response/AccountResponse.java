package com.koriebruh.accountservice.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

/**
 * Response for account endpoints.
 * depositDetail and rdnDetail are null for non-applicable account types.
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccountResponse {

    @JsonProperty("account_number")
    private String accountNumber;

    @JsonProperty("account_type")
    private String accountType;

    @JsonProperty("balance")
    private BigDecimal balance;

    @JsonProperty("currency")
    private String currency;

    @JsonProperty("status")
    private String status;

    @JsonProperty("created_at")
    private Instant createdAt;

    @JsonProperty("updated_at")
    private Instant updatedAt;

    // Populated only for DEPOSIT accounts
    @JsonProperty("deposit_detail")
    private DepositDetailResponse depositDetail;

    // Populated only for RDN accounts
    @JsonProperty("rdn_detail")
    private RdnDetailResponse rdnDetail;

    // -------------------------------------------------------------------------
    // Nested response blocks
    // -------------------------------------------------------------------------

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class DepositDetailResponse {

        @JsonProperty("principal_amount")
        private BigDecimal principalAmount;

        @JsonProperty("interest_rate")
        private BigDecimal interestRate;

        @JsonProperty("tenor_months")
        private Short tenorMonths;

        @JsonProperty("maturity_date")
        private LocalDate maturityDate;

        @JsonProperty("interest_payout")
        private String interestPayout;

        @JsonProperty("auto_rollover")
        private Boolean autoRollover;
    }

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class RdnDetailResponse {

        @JsonProperty("sid")
        private String sid;

        @JsonProperty("securities_company")
        private String securitiesCompany;

        @JsonProperty("verified_at")
        private Instant verifiedAt;
    }
}