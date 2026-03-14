package com.koriebruh.accountservice.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.koriebruh.accountservice.entity.enums.AccountStatus;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateAccountStatusRequest {

    @NotNull(message = "Status is required")
    @JsonProperty("status")
    private AccountStatus status;
}
