package com.koriebruh.accountservice.grpc;

import com.koriebruh.accountservice.repository.AccountRepository;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.grpc.server.service.GrpcService;

import java.math.BigDecimal;

@GrpcService
@RequiredArgsConstructor
@Slf4j
public class AccountGrpcServiceImpl extends AccountGrpcServiceGrpc.AccountGrpcServiceImplBase {

    private final AccountRepository accountRepository;

    @Override
    public void validateAccount(ValidateAccountRequest request,
                                StreamObserver<ValidateAccountResponse> responseObserver) {
        BigDecimal requestedAmount = new BigDecimal(request.getAmount());

        accountRepository.findByAccountNumber(request.getAccountNumber())
                .map(account -> {
                    if (!account.isOperational()) {
                        return ValidateAccountResponse.newBuilder()
                                .setValid(false)
                                .setReason(account.getStatus().name())
                                .build();
                    }
                    if (!account.hasSufficientBalance(requestedAmount)) {
                        return ValidateAccountResponse.newBuilder()
                                .setValid(false)
                                .setReason("INSUFFICIENT_BALANCE")
                                .build();
                    }
                    return ValidateAccountResponse.newBuilder()
                            .setValid(true)
                            .setAccountId(account.getId().toString())
                            .setCurrentBalance(account.getBalance().toPlainString())
                            .build();
                })
                .defaultIfEmpty(
                        ValidateAccountResponse.newBuilder()
                                .setValid(false)
                                .setReason("ACCOUNT_NOT_FOUND")
                                .build()
                )
                .subscribe(
                        response -> {
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("[gRPC] validateAccount error: {}", error.getMessage());
                            responseObserver.onError(
                                    Status.INTERNAL
                                            .withDescription(error.getMessage())
                                            .asRuntimeException()
                            );
                        }
                );
    }

    @Override
    public void getAccountDetail(GetAccountDetailRequest request,
                                 StreamObserver<AccountDetailResponse> responseObserver) {
        accountRepository.findByAccountNumber(request.getAccountNumber())
                .subscribe(
                        account -> {
                            responseObserver.onNext(
                                    AccountDetailResponse.newBuilder()
                                            .setAccountId(account.getId().toString())
                                            .setAccountNumber(account.getAccountNumber())
                                            .setUserId(account.getUserId().toString())
                                            .setAccountType(account.getAccountType().name())
                                            .setStatus(account.getStatus().name())
                                            .setBalance(account.getBalance().toPlainString())
                                            .setCurrency(account.getCurrency())
                                            .build()
                            );
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("[gRPC] getAccountDetail error: {}", error.getMessage());
                            responseObserver.onError(
                                    Status.INTERNAL
                                            .withDescription(error.getMessage())
                                            .asRuntimeException()
                            );
                        },
                        () -> responseObserver.onError(
                                Status.NOT_FOUND
                                        .withDescription("Account not found: " + request.getAccountNumber())
                                        .asRuntimeException()
                        )
                );
    }
}
