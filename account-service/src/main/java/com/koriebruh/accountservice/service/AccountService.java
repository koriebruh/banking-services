package com.koriebruh.accountservice.service;

import com.koriebruh.accountservice.entity.AccountTransaction;
import com.koriebruh.accountservice.event.AccountEventPublisher;
import com.koriebruh.accountservice.repository.AccountRepository;
import com.koriebruh.accountservice.repository.AccountTransactionRepository;
import com.koriebruh.accountservice.repository.DepositDetailRepository;
import com.koriebruh.accountservice.repository.RdnDetailRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountService {

    private final AccountRepository accountRepository;

    private final AccountTransactionRepository accountTransaction;

    private final DepositDetailRepository depositDetailRepository;

    private final RdnDetailRepository rdnDetailRepository;

    private final AccountEventPublisher accountEventPublisher;



    // -------------------------------------------------------------------------
    // ACCOUNT MANAGEMENT
    // -------------------------------------------------------------------------



    // OPEN NEW ACCOUNT

    // LIST ALL ACCOUNTS

    // DETAILS FOR ONE ACCOUNT

    // UPDATE STATUS (ACTIVE, FROZEN, CLOSED) ABLE ADMIN ONLY





    // -------------------------------------------------------------------------
    // MUTATION & HISTORY
    // -------------------------------------------------------------------------


    // LIST HISTORY TRANSACTIONS FOR ACCOUNT


    // DETAIL HISTORY FOR ONE TRANSACTION

}

