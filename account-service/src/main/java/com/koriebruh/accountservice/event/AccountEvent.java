package com.koriebruh.accountservice.event;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;


/**
 * Base event payload published to Kafka for all account domain events.
 *
 * <p>Consumed by:
 * <ul>
 *   <li><b>audit-service</b>   — persists all events into append-only audit log.</li>
 *   <li><b>notif-service</b>   — sends notifications to customers on relevant events.</li>
 * </ul>
 *
 * <p><b>Notes:</b>
 * <ul>
 *   <li>event_id is a UUID for idempotency — consumers must deduplicate on this field.</li>
 *   <li>event_version enables schema evolution without breaking existing consumers.</li>
 *   <li>user_code is used instead of user_id — non-sensitive business identifier, safe to log.</li>
 *   <li>metadata carries event-specific payload (e.g. account type, amount) — nullable.</li>
 * </ul>
 */

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountEvent {

    @JsonProperty("event_id")
    private String eventId;           // UUID — idempotency key for consumers

    @JsonProperty("event_type")
    private String eventType;         // one of AccountEventType constants

    @JsonProperty("event_version")
    private String eventVersion;      // schema version, e.g. "v1"

    @JsonProperty("occurred_at")
    private Instant occurredAt;       // UTC timestamp of when the event happened

    @JsonProperty("user_code")
    private String userCode;          // business identifier, e.g. USR-20260308-00001, only for messaging

    @JsonProperty("account_number")
    private String accountNumber;     // the account involved in the event

    @JsonProperty("account_type")
    private String accountType;       // SAVINGS | CURRENT | DEPOSIT | RDN

    @JsonProperty("metadata")
    private Object metadata;

}
