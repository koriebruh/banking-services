package com.koriebruh.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaSetupVerifyResponse {

    @JsonProperty("mfa_enabled")
    private Boolean mfaEnabled;

    @JsonProperty("message")
    private String message;
}