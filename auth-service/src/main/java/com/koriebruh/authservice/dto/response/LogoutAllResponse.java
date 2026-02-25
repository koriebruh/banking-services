package com.koriebruh.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

/**
 * Response DTO for logout all devices operation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogoutAllResponse {

    @JsonProperty("revoked_tokens_count")
    private Integer revokedTokensCount;

    @JsonProperty("logged_out_at")
    private ZonedDateTime loggedOutAt;
}

