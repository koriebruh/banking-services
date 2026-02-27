package com.koriebruh.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Response DTO returned by the /api/auth/login endpoint.
 *
 * <p>This response supports both MFA-enabled and non-MFA authentication flows.</p>
 *
 * <p><b>Behavior:</b></p>
 * <ul>
 *   <li>If MFA is NOT enabled, the response returns access and refresh tokens.</li>
 *   <li>If MFA is enabled, the response returns a temporary MFA token
 *       that must be verified before issuing access and refresh tokens.</li>
 * </ul>
 *
 * <p><b>Example (MFA disabled):</b></p>
 * <pre>
 * {
 *   "mfa_required": false,
 *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "expires_in": 3600
 * }
 * </pre>
 *
 * <p><b>Example (MFA enabled):</b></p>
 * <pre>
 * {
 *   "mfa_required": true,
 *   "mfa_token": "temporary.jwt.token"
 * }
 * </pre>
 *
 * <p><b>Notes:</b></p>
 * <ul>
 *   <li>Null fields are omitted from the JSON response.</li>
 *   <li>The mfa_token is short-lived and only valid for MFA verification.</li>
 * </ul>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {

    @JsonProperty("mfa_required")
    private Boolean mfaRequired;

    @JsonProperty("mfa_token")
    private String mfaToken;

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("expires_in")
    private Long expiresIn;
}

