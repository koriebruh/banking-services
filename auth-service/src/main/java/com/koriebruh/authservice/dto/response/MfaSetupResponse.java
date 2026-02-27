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
public class MfaSetupResponse {

    @JsonProperty("qr_code")
    private String qrCode; // base64 PNG — render dengan <img src="data:image/png;base64,{qrCode}" />

    @JsonProperty("secret")
    private String secret;

}
