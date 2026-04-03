package com.koriebruh.accountservice.repository;

import com.koriebruh.accountservice.entity.BalanceLedger;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;


@Repository
public interface BalanceLedgerRepository extends R2dbcRepository<BalanceLedger, UUID> {

    /**
     * Idempotency check — returns true if reference_id already exists.
     * Used by Kafka consumer to skip duplicate transfer.event redeliveries.
     */
    Mono<Boolean> existsByReferenceId(String referenceId);

    /**
     * Latest ledger entry for an account.
     * Used to verify account.balance == balance_ledger.balance_after.
     */
    Mono<BalanceLedger> findTopByAccountIdOrderByCreatedAtDesc(UUID accountId);
}

