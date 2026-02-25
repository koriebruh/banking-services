package com.koriebruh.authservice.exception;

/**
 * Base class for all user-related business exceptions.
 * This is a domain-level exception (NOT tied to HTTP).
 */
public class UserExceptions extends RuntimeException {

    public UserExceptions(String message) {
        super(message);
    }

    public static class DuplicateNikException extends UserExceptions {
        public DuplicateNikException(String nik) {
            super("NIK '" + nik + "' is already registered");
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
