package com.koriebruh.authservice.event;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthEvent {

    @JsonProperty("event_id")
    private String eventId;         // UUID — untuk idempotency di consumer

    @JsonProperty("event_type")
    private String eventType;       // user.registered, user.login.success, dll

    @JsonProperty("event_version")
    private String eventVersion;    // "v1" — untuk schema evolution

    @JsonProperty("occurred_at")
    private Instant occurredAt;     // waktu event terjadi

    @JsonProperty("user_code")
    private String userCode;        // business ID, bukan UUID internal

    @JsonProperty("email")
    private String email;           // masked — k*******h@gmail.com

    @JsonProperty("ip_address")
    private String ipAddress;

    @JsonProperty("user_agent")
    private String userAgent;

    @JsonProperty("metadata")
    private Object metadata;        // payload tambahan per event type
}