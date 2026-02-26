package com.koriebruh.authservice.exception;

import java.time.Instant;

/**
 * Base class for all user-related business exceptions.
 * This is a domain-level exception (NOT tied to HTTP).
 */
public class UserExceptions extends RuntimeException {

    public UserExceptions(String message) {
        super(message);
    }

    public static class AccountLockedException extends UserExceptions {
        public AccountLockedException(Instant lockedUntil) {
            super("Account is locked until " + lockedUntil);
        }
    }

    public static class UnactivatedException extends UserExceptions {
        public UnactivatedException() {
            super("Account is not activated tell an Teller to activate your account");
        }
    }

    public static class DuplicateNikException extends UserExceptions {
        public DuplicateNikException(String nik) {
            super("NIK '" + nik + "' is already registered");
        }
    }

    public static class LoginFailException extends UserExceptions {
        public LoginFailException() {
            super("Email or Password is incorrect");
        }
    }

    public static class DuplicateEmailException extends UserExceptions {
        public DuplicateEmailException(String email) {
            super("Email '" + email + "' is already registered");
        }
    }

    public static class DuplicatePhoneNumberException extends UserExceptions {
        public DuplicatePhoneNumberException(String phoneNumber) {
            super("Phone number '" + phoneNumber + "' is already registered");
        }
    }
}
