package com.koriebruh.accountservice.event;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.util.UUID;

/**
 * Publishes account domain events to Kafka asynchronously.
 *
 * <p><b>Design decisions:</b>
 * <ul>
 *   <li>Uses {@code Schedulers.boundedElastic()} — KafkaTemplate.send() is blocking
 *       under the hood and must not run on the reactor event loop thread.</li>
 *   <li>Publish is <b>fire-and-forget</b> — failures are logged but never propagate
 *       to the caller. The business transaction has already committed at this point.</li>
 *   <li>Partition key = accountNumber — guarantees ordered delivery per account.</li>
 *   <li>topic and eventVersion are loaded from config, never hardcoded (12-Factor App).</li>
 * </ul>
 *
 * <p><b>Failure handling:</b> If Kafka is unavailable, the event is logged for
 * manual replay. For guaranteed delivery, consider the Outbox Pattern as a future improvement.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AccountEventPublisher {

    private final KafkaTemplate<String, AccountEvent> kafkaTemplate;

    @Value("${app.kafka.topic-produce.account-events}")
    private String topic;

    @Value("${app.event.version}")
    private String eventVersion;

    /**
     * Publishes an account event to Kafka.
     *
     * <p><b>Flow:</b> AccountService (after business commit) → publish() → Kafka → consumers
     * <p><b>Security:</b> No sensitive data (balance, personal info) should be passed as metadata.
     *
     * @param eventType     one of the constants in {@link AccountEventType}
     * @param userCode      business user identifier, e.g. USR-20260308-00001
     * @param accountNumber the account involved in the event
     * @param accountType   account type string, e.g. "SAVINGS"
     * @param metadata      event-specific payload, nullable
     * @return empty Mono — fire-and-forget, always completes without error
     */
    public Mono<Void> publish(String eventType,
                              String userCode,
                              String accountNumber,
                              String accountType,
                              Object metadata) {

        AccountEvent event = AccountEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(eventType)
                .eventVersion(eventVersion)
                .occurredAt(Instant.now())
                .userCode(userCode)
                .accountNumber(accountNumber)
                .accountType(accountType)
                .metadata(metadata)
                .build();

        return Mono.fromRunnable(() ->
                kafkaTemplate.send(topic, accountNumber, event)   // partition key = accountNumber
                        .whenComplete((result, ex) -> {
                            if (ex != null) {
                                // NON-FATAL — log for dead-letter / manual replay
                                log.error("Failed to publish Kafka event. eventType={}, accountNumber={}, reason={}",
                                        eventType, accountNumber, ex.getMessage());
                            } else {
                                log.debug("Kafka event published. eventType={}, accountNumber={}, offset={}",
                                        eventType, accountNumber,
                                        result.getRecordMetadata().offset());
                            }
                        })
        ).subscribeOn(Schedulers.boundedElastic()).then();
    }
}