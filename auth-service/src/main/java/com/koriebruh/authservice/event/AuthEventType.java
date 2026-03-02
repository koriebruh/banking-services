package com.koriebruh.authservice.event;

public final class AuthEventType {

    private AuthEventType() {
    }

    public static final String USER_REGISTERED = "user.registered";
    public static final String LOGIN_SUCCESS = "user.login.success";
    public static final String LOGIN_FAILED = "user.login.failed";
    public static final String PASSWORD_CHANGED = "user.password.changed";
    public static final String PASSWORD_RESET = "user.password.reset";
    public static final String MFA_ENABLED = "user.mfa.enabled";
    public static final String MFA_VALIDATED = "user.mfa.validated";
    public static final String ACCOUNT_LOCKED = "user.account.locked";
    public static final String LOGOUT = "user.logout";
}
