package com.koriebruh.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Response DTO for successful login.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    @JsonProperty("mfa_required")
    private boolean mfaRequired;

    @JsonProperty("mfa_token")
    private String mfaToken;

    @JsonProperty("expires_in")
    private Long expiresIn;
}

