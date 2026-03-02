package com.koriebruh.authservice.event;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import org.springframework.beans.factory.annotation.Value;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthEventPublisher {

    private final KafkaTemplate<String, AuthEvent> kafkaTemplate;

    @Value("${app.kafka.topic.auth-events}")
    private String TOPIC;

    @Value("${app.kafka.event.version}")
    private String eventVersion;


    /**
     * Publishes an auth event to Kafka asynchronously.
     *
     * <p>Uses {@code Schedulers.boundedElastic()} because KafkaTemplate
     * is blocking under the hood — must not run on the reactor event loop.
     *
     * <p>Event publish failure is intentionally non-fatal:
     * the main business transaction has already committed at this point.
     * Failed events are logged for manual replay or dead-letter handling.
     *
     * @param eventType one of the constants in {@link AuthEventType}
     * @param userCode  business user identifier
     * @param email     masked email address
     * @param ipAddress originating IP (nullable for non-login events)
     * @param userAgent originating user-agent (nullable for non-login events)
     * @param metadata  additional event-specific payload (nullable)
     * @return empty {@link Mono} — fire-and-forget
     */
    public Mono<Void> publish(String eventType,
                              String userCode,
                              String email,
                              String ipAddress,
                              String userAgent,
                              Object metadata) {

        AuthEvent event = AuthEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(eventType)
                .eventVersion(eventVersion)
                .occurredAt(Instant.now())
                .userCode(userCode)
                .email(email)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .metadata(metadata)
                .build();

        return Mono.fromRunnable(() ->
                kafkaTemplate.send(TOPIC, event.getUserCode(), event)
                        .whenComplete((result, ex) -> {
                            if (ex != null) {
                                // NON-FATAL — log for dead-letter / manual replay
                                log.error("Failed to publish Kafka event. eventType={}, userCode={}, reason={}",
                                        eventType, userCode, ex.getMessage());
                            } else {
                                log.debug("Kafka event published. eventType={}, userCode={}, offset={}",
                                        eventType, userCode,
                                        result.getRecordMetadata().offset());
                            }
                        })
        ).subscribeOn(Schedulers.boundedElastic()).then();
    }
}