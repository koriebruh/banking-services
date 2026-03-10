package com.koriebruh.accountservice.dto.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.koriebruh.accountservice.entity.enums.AccountType;
import com.koriebruh.accountservice.entity.enums.InterestPayoutType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

/**
 * Request body for POST /api/v1/accounts.
 *
 * <p>userId is NOT taken from request body — extracted from JWT principal.
 * depositDetail required only when accountType = DEPOSIT.
 * rdnDetail required only when accountType = RDN.
 */
@Data
public class OpenAccountRequest {

    @NotNull(message = "Account type is required")
    @JsonProperty("account_type")
    private AccountType accountType;

    @Valid
    @JsonProperty("deposit_detail")
    private DepositDetailRequest depositDetail;

    @Valid
    @JsonProperty("rdn_detail")
    private RdnDetailRequest rdnDetail;

    @Data
    public static class DepositDetailRequest {

        @NotNull(message = "Principal amount is required")
        @DecimalMin(value = "1000000.00", message = "Minimum deposit is IDR 1,000,000")
        @JsonProperty("principal_amount")
        private BigDecimal principalAmount;

        @NotNull(message = "Tenor is required")
        @JsonProperty("tenor_months")
        private Short tenorMonths;

        @NotNull(message = "Interest payout type is required")
        @JsonProperty("interest_payout")
        private InterestPayoutType interestPayout;

        @JsonProperty("auto_rollover")
        private Boolean autoRollover = false;
    }

    @Data
    public static class RdnDetailRequest {

        @NotNull(message = "SID is required")
        private String sid;

        @NotNull(message = "Securities company is required")
        @JsonProperty("securities_company")
        private String securitiesCompany;
    }
}