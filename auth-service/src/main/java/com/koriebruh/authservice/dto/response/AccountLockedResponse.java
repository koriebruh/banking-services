package com.koriebruh.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

/**
 * Response DTO for account locked scenario.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccountLockedResponse {

    @JsonProperty("locked_until")
    private ZonedDateTime lockedUntil;

    @JsonProperty("failed_attempts")
    private Integer failedAttempts;
}

