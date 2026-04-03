package com.koriebruh.accountservice.event;

import com.koriebruh.accountservice.entity.BalanceLedger;
import com.koriebruh.accountservice.repository.AccountRepository;
import com.koriebruh.accountservice.repository.BalanceLedgerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Consumes transfer.event from transaction-service.
 *
 * Flow per event:
 *   1. Check balance_ledger for reference_id (idempotency guard)
 *   2. Debit source account + insert ledger entry (negative amount)
 *   3. Credit target account + insert ledger entry (positive amount)
 *   4. Acknowledge Kafka offset only after both writes succeed
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TransferEventConsumer {

    private final AccountRepository accountRepository;
    private final BalanceLedgerRepository balanceLedgerRepository;
    private final TransactionalOperator transactionalOperator;

    @KafkaListener(
            topics = "transfer.event",
            groupId = "account-service",
            containerFactory = "transferEventListenerFactory"
    )
    public void consume(ConsumerRecord<String, TransferEvent> record, Acknowledgment ack) {
        TransferEvent event = record.value();
        log.info("Received transfer.event referenceId={}", event.getReferenceId());

        balanceLedgerRepository.existsByReferenceId(event.getReferenceId())
                .flatMap(exists -> {
                    if (exists) {
                        log.warn("Duplicate transfer.event skipped referenceId={}", event.getReferenceId());
                        return Mono.empty();
                    }
                    return processDebit(event)
                            .then(processCredit(event));
                })
                .as(transactionalOperator::transactional)
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe(
                        unused -> {},
                        error -> log.error("Failed to process transfer.event referenceId={}, reason={}",
                                event.getReferenceId(), error.getMessage()),
                        () -> ack.acknowledge()
                );
    }

    private Mono<Void> processDebit(TransferEvent event) {
        return accountRepository.findByAccountNumberForUpdate(event.getSourceAccountNumber())
                .flatMap(account -> {
                    BigDecimal newBalance = account.getBalance().subtract(event.getAmount());
                    BigDecimal debitAmount = event.getAmount().negate(); // negative = DEBIT

                    BalanceLedger ledger = BalanceLedger.builder()
                            .accountId(account.getId())
                            .amount(debitAmount)
                            .balanceBefore(account.getBalance())
                            .balanceAfter(newBalance)
                            .referenceId(event.getReferenceId() + ":debit")
                            .createdAt(Instant.now())
                            .build();

                    return accountRepository.updateBalanceWithOptimisticLock(
                                    account.getId(), newBalance, account.getBalance())
                            .then(balanceLedgerRepository.save(ledger));
                })
                .then();
    }

    private Mono<Void> processCredit(TransferEvent event) {
        return accountRepository.findByAccountNumber(event.getTargetAccountNumber())
                .flatMap(account -> {
                    BigDecimal newBalance = account.getBalance().add(event.getAmount());

                    BalanceLedger ledger = BalanceLedger.builder()
                            .accountId(account.getId())
                            .amount(event.getAmount()) // positive = CREDIT
                            .balanceBefore(account.getBalance())
                            .balanceAfter(newBalance)
                            .referenceId(event.getReferenceId() + ":credit")
                            .createdAt(Instant.now())
                            .build();

                    return accountRepository.updateBalanceWithOptimisticLock(
                                    account.getId(), newBalance, account.getBalance())
                            .then(balanceLedgerRepository.save(ledger));
                })
                .then();
    }
}