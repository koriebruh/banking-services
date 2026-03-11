package com.koriebruh.accountservice.service;

import com.koriebruh.accountservice.dto.request.OpenAccountRequest;
import com.koriebruh.accountservice.dto.response.AccountResponse;
import com.koriebruh.accountservice.entity.Account;
import com.koriebruh.accountservice.entity.AccountTransaction;
import com.koriebruh.accountservice.entity.DepositDetail;
import com.koriebruh.accountservice.entity.RdnDetail;
import com.koriebruh.accountservice.entity.enums.AccountStatus;
import com.koriebruh.accountservice.entity.enums.AccountType;
import com.koriebruh.accountservice.event.AccountEventPublisher;
import com.koriebruh.accountservice.event.AccountEventType;
import com.koriebruh.accountservice.exception.AccountExceptions;
import com.koriebruh.accountservice.repository.AccountRepository;
import com.koriebruh.accountservice.repository.AccountTransactionRepository;
import com.koriebruh.accountservice.repository.DepositDetailRepository;
import com.koriebruh.accountservice.repository.RdnDetailRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountService {

    private final AccountRepository accountRepository;

    private final AccountTransactionRepository accountTransaction;

    private final DepositDetailRepository depositDetailRepository;

    private final RdnDetailRepository rdnDetailRepository;

    private final AccountEventPublisher eventPublisher;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MAX_ACCOUNT_NUMBER_RETRY = 5;


    // -------------------------------------------------------------------------
    // ACCOUNT MANAGEMENT
    // -------------------------------------------------------------------------

    /**
     * Opens a new bank account for the authenticated user.
     *
     * <p><b>Flow:</b>
     * <ol>
     *   <li>Validate type-specific fields (DEPOSIT requires depositDetail, RDN requires rdnDetail).</li>
     *   <li>Check if user already has an ACTIVE or FROZEN account of the same type — reject if exists.</li>
     *   <li>Generate unique 10-digit account number (max 5 retries).</li>
     *   <li>Save account entity.</li>
     *   <li>If DEPOSIT — save deposit_detail.</li>
     *   <li>If RDN — validate SID uniqueness and save rdn_detail.</li>
     *   <li>Publish ACCOUNT_OPENED event to Kafka (fire-and-forget, failures are logged only).</li>
     * </ol>
     *
     * <p><b>Security:</b> userId extracted from JWT principal — never from request body.
     *
     * <p><b>Consistency:</b> Entire operation runs in a reactive transaction.
     * If saveTypeSpecificDetail fails, the account insert is rolled back.
     * DB-level UNIQUE constraints on (user_id, account_type) and (sid) serve as
     * last-line-of-defense against race conditions.
     *
     * @param request  validated open account request
     * @param userId   authenticated user ID from JWT
     * @param userCode business user identifier from JWT, used for Kafka event
     * @return account response with type-specific detail
     */
    @Transactional
    public Mono<AccountResponse> openAccount(OpenAccountRequest request, UUID userId, String userCode) {
        // VALIDATE TYPE-SPECIFIC FIELDS BEFORE ANY DB OPERATION
        return validateTypeSpecificRequest(request)
                // CHECK FOR EXISTING ACTIVE/FROZEN ACCOUNT
                .then(accountRepository.existsByUserIdAndAccountTypeAndStatusIn(
                        userId,
                        request.getAccountType(),
                        List.of(AccountStatus.ACTIVE, AccountStatus.FROZEN)
                )).flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new AccountExceptions.AccountTypeAlreadyExistsException(
                                request.getAccountType().name()
                        ));
                    }
                    return Mono.empty();
                })
                // CREATE ACCOUNT ENTITY
                .then(generateUniqueAccountNumber(0))
                .flatMap(accountNumber -> {
                    Account account = Account.builder()
                            .accountNumber(accountNumber)
                            .userId(userId)
                            .accountType(request.getAccountType())
                            .balance(initialBalance(request))
                            .currency("IDR")
                            .status(AccountStatus.ACTIVE)
                            .build();
                    return accountRepository.save(account);
                })
                .flatMap(saved -> saveTypeSpecificDetail(saved, request).thenReturn(saved))
                .flatMap(this::buildAccountResponse)
                // PUBLISH EVENT AFTER SUCCESSFUL CREATION — fire-and-forget, log any failure
                .doOnSuccess(response -> eventPublisher.publish(
                        AccountEventType.ACCOUNT_OPENED,
                        userCode,
                        response.getAccountNumber(),
                        response.getAccountType(),
                        Map.of("currency", "IDR")
                ).subscribe(
                        null,
                        err -> log.error("[AccountService] Failed to publish ACCOUNT_OPENED event. " +
                                "accountNumber={}", response.getAccountNumber(), err)
                ))
                // HANDLE UNIQUE CONSTRAINT VIOLATION (EITHER ACCOUNT NUMBER OR RDN SID)
                .onErrorMap(DataIntegrityViolationException.class, ex -> {
                    String msg = ex.getMessage() != null ? ex.getMessage().toLowerCase() : "";

                    if (msg.contains("uq_rdn_sid")) {
                        log.warn("[AccountService] Duplicate SID via DB constraint. userId={}", userId);
                        return new AccountExceptions.DuplicateSidException(request.getRdnDetail().getSid());
                    }

                    log.warn("[AccountService] Duplicate account type via DB constraint. userId={}, type={}",
                            userId, request.getAccountType());
                    return new AccountExceptions.AccountTypeAlreadyExistsException(
                            request.getAccountType().name()
                    );
                })
                .doOnSuccess(r -> log.info("[AccountService] Account opened. " +
                        "accountNumber={}, type={}, userId={}", r.getAccountNumber(), r.getAccountType(), userId));
    }

    // OPEN NEW ACCOUNT

    // LIST ALL ACCOUNTS

    // DETAILS FOR ONE ACCOUNT

    // UPDATE STATUS (ACTIVE, FROZEN, CLOSED) ABLE ADMIN ONLY


    // -------------------------------------------------------------------------
    // MUTATION & HISTORY
    // -------------------------------------------------------------------------


    // LIST HISTORY TRANSACTIONS FOR ACCOUNT


    // DETAIL HISTORY FOR ONE TRANSACTION


    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================


    /**
     * Validates type-specific fields before opening an account.
     * Ensures DEPOSIT has depositDetail and RDN has rdnDetail.
     */
    private Mono<Void> validateTypeSpecificRequest(OpenAccountRequest request) {
        if (request.getAccountType() == AccountType.DEPOSIT && request.getDepositDetail() == null) {
            return Mono.error(new IllegalArgumentException("depositDetail is required for DEPOSIT accounts"));
        }
        if (request.getAccountType() == AccountType.RDN && request.getRdnDetail() == null) {
            return Mono.error(new IllegalArgumentException("rdnDetail is required for RDN accounts"));
        }
        return Mono.empty();
    }

    /**
     * Generates a unique 10-digit account number.
     * Fails fast after MAX_ACCOUNT_NUMBER_RETRY attempts.
     */
    private Mono<String> generateUniqueAccountNumber(int attempt) {
        if (attempt >= MAX_ACCOUNT_NUMBER_RETRY) {
            return Mono.error(new AccountExceptions.AccountNumberGenerationException(MAX_ACCOUNT_NUMBER_RETRY));
        }
        return Mono.defer(() -> {
            String candidate = String.format("%010d", Math.abs(RANDOM.nextLong()) % 10_000_000_000L);
            return accountRepository.existsByAccountNumber(candidate)
                    .flatMap(exists -> exists
                            ? generateUniqueAccountNumber(attempt + 1)
                            : Mono.just(candidate));
        });
    }

    /**
     * Returns initial balance:
     * - DEPOSIT: principal amount (locked at opening)
     * - Others: 0
     */
    private BigDecimal initialBalance(OpenAccountRequest request) {
        if (request.getAccountType() == AccountType.DEPOSIT && request.getDepositDetail() != null) {
            return request.getDepositDetail().getPrincipalAmount()
                    .setScale(4, RoundingMode.HALF_UP);
        }
        return BigDecimal.ZERO.setScale(4, RoundingMode.HALF_UP);
    }

    /**
     * Saves type-specific detail (deposit_detail or rdn_detail) after account is saved.
     * SAVINGS and CURRENT have no extra detail — returns Mono.empty().
     */
    private Mono<Void> saveTypeSpecificDetail(Account saved, OpenAccountRequest request) {
        return switch (saved.getAccountType()) {
            case DEPOSIT -> {
                OpenAccountRequest.DepositDetailRequest d = request.getDepositDetail();
                // Interest rate is determined by business rules — hardcoded for now
                BigDecimal interestRate = resolveInterestRate(d.getTenorMonths());
                LocalDate maturityDate = LocalDate.now().plusMonths(d.getTenorMonths());

                DepositDetail detail = DepositDetail.builder()
                        .accountId(saved.getId())
                        .principalAmount(d.getPrincipalAmount().setScale(4, RoundingMode.HALF_UP))
                        .interestRate(interestRate)
                        .tenorMonths(d.getTenorMonths())
                        .maturityDate(maturityDate)
                        .interestPayout(d.getInterestPayout())
                        .autoRollover(d.getAutoRollover())
                        .build();

                yield depositDetailRepository.save(detail).then();
            }
            case RDN -> {
                OpenAccountRequest.RdnDetailRequest r = request.getRdnDetail();

                yield rdnDetailRepository.existsBySid(r.getSid())
                        .flatMap(exists -> {
                            if (exists) {
                                return Mono.error(new AccountExceptions.DuplicateSidException(r.getSid()));
                            }
                            RdnDetail detail = RdnDetail.builder()
                                    .accountId(saved.getId())
                                    .sid(r.getSid())
                                    .securitiesCompany(r.getSecuritiesCompany())
                                    .build();
                            return rdnDetailRepository.save(detail);
                        }).then();
            }
            default -> Mono.empty();
        };
    }

    /**
     * Builds AccountResponse including type-specific detail if applicable.
     */
    private Mono<AccountResponse> buildAccountResponse(Account account) {
        AccountResponse.AccountResponseBuilder builder = AccountResponse.builder()
                .accountNumber(account.getAccountNumber())
                .accountType(account.getAccountType().name())
                .balance(account.getBalance())
                .currency(account.getCurrency())
                .status(account.getStatus().name())
                .createdAt(account.getCreatedAt())
                .updatedAt(account.getUpdatedAt());

        return switch (account.getAccountType()) {
            case DEPOSIT -> depositDetailRepository.findByAccountId(account.getId())
                    .map(d -> builder.depositDetail(AccountResponse.DepositDetailResponse.builder()
                            .principalAmount(d.getPrincipalAmount())
                            .interestRate(d.getInterestRate())
                            .tenorMonths(d.getTenorMonths())
                            .maturityDate(d.getMaturityDate())
                            .interestPayout(d.getInterestPayout().name())
                            .autoRollover(d.getAutoRollover())
                            .build()).build())
                    .defaultIfEmpty(builder.build());

            case RDN -> rdnDetailRepository.findByAccountId(account.getId())
                    .map(r -> builder.rdnDetail(AccountResponse.RdnDetailResponse.builder()
                            .sid(r.getSid())
                            .securitiesCompany(r.getSecuritiesCompany())
                            .verifiedAt(r.getVerifiedAt())
                            .build()).build())
                    .defaultIfEmpty(builder.build());

            default -> Mono.just(builder.build());
        };
    }

    /**
     * Resolves annual interest rate based on deposit tenor.
     * In production this should be loaded from a rate config table.
     *
     * @param tenorMonths deposit tenor in months
     * @return annual interest rate as BigDecimal
     */
    private BigDecimal resolveInterestRate(Short tenorMonths) {
        return switch (tenorMonths) {
            case 1 -> new BigDecimal("3.50");
            case 3 -> new BigDecimal("4.00");
            case 6 -> new BigDecimal("4.75");
            case 12 -> new BigDecimal("5.25");
            case 24 -> new BigDecimal("5.50");
            default -> new BigDecimal("3.50");
        };
    }


}

