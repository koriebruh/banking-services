package com.koriebruh.accountservice.event;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Kafka event payload consumed from topic: transfer.event
 * Published by transaction-service after a transfer is processed.
 *
 * reference_id is the idempotency key — used to prevent double-posting
 * in balance_ledger on Kafka redelivery.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransferEvent {

    @JsonProperty("reference_id")
    private String referenceId;         // idempotency key

    @JsonProperty("source_account_number")
    private String sourceAccountNumber; // account to debit (negative amount)

    @JsonProperty("target_account_number")
    private String targetAccountNumber; // account to credit (positive amount)

    @JsonProperty("amount")
    private BigDecimal amount;          // always positive, direction handled by sign

    @JsonProperty("currency")
    private String currency;

    @JsonProperty("occurred_at")
    private Instant occurredAt;
}