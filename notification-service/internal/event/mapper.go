package event

import "fmt"

// ── Auth Event Mapper ─────────────────────────────────────────────────────────
//
// Routing rationale (banking best practice):
//
//	event                  | EMAIL | WS
//	-----------------------|-------|----
//	user.registered        |  ✅   | ✅   welcome email + real-time onboarding prompt
//	user.login.success     |  ❌   | ✅   terlalu frequent untuk email; WS sebagai activity feed
//	user.login.failed      |  ✅   | ✅   security alert penting
//	user.password.changed  |  ✅   | ✅   konfirmasi perubahan sensitif
//	user.password.reset    |  ✅   | ✅   konfirmasi reset
//	user.mfa.enabled       |  ✅   | ✅   konfirmasi security upgrade
//	user.mfa.validated     |  ❌   | ✅   transient, tidak perlu email
//	user.account.locked    |  ✅   | ✅   critical alert
//	user.logout            |  ❌   | ❌   tidak perlu notifikasi
func MapAuthEvent(e AuthEvent, email string) []Notification {
	base := map[string]any{
		"user_code":  e.UserCode,
		"event_type": string(e.EventType),
		"occurred_at": e.OccurredAt.Format("02 Jan 2006 15:04 WIB"),
		"ip_address": e.IPAddress,
	}

	var notifications []Notification

	switch e.EventType {

	case AuthUserRegistered:
		notifications = append(notifications,
			wsNotif(e.UserCode, "Selamat datang di Banking Service!", "user_registered", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, "Selamat Datang di Banking Service 🎉", "user_registered", base),
			)
		}

	case AuthLoginSuccess:
		// Only WS — email terlalu noisy untuk setiap login
		notifications = append(notifications,
			wsNotif(e.UserCode, "Login berhasil", "login_success", base),
		)

	case AuthLoginFailed:
		notifications = append(notifications,
			wsNotif(e.UserCode, "Percobaan login gagal terdeteksi", "login_failed", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, "⚠️ Percobaan Login Gagal Terdeteksi", "login_failed", base),
			)
		}

	case AuthPasswordChange:
		notifications = append(notifications,
			wsNotif(e.UserCode, "Password berhasil diubah", "password_changed", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, "Password Anda Telah Diubah", "password_changed", base),
			)
		}

	case AuthPasswordReset:
		notifications = append(notifications,
			wsNotif(e.UserCode, "Password berhasil direset", "password_reset", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, "Konfirmasi Reset Password", "password_reset", base),
			)
		}

	case AuthMfaEnabled:
		notifications = append(notifications,
			wsNotif(e.UserCode, "Two-Factor Authentication diaktifkan", "mfa_enabled", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, "🔐 Autentikasi Dua Faktor Diaktifkan", "mfa_enabled", base),
			)
		}

	case AuthMfaValidated:
		// Only WS — transient confirmation, tidak perlu email
		notifications = append(notifications,
			wsNotif(e.UserCode, "Verifikasi MFA berhasil", "mfa_validated", base),
		)

	case AuthAccountLocked:
		notifications = append(notifications,
			wsNotif(e.UserCode, "Akun Anda telah dikunci", "account_locked", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, "🚨 Akun Anda Telah Dikunci", "account_locked", base),
			)
		}

	case AuthLogout:
		// Tidak memerlukan notifikasi
	}

	return notifications
}

// ── Account Event Mapper ──────────────────────────────────────────────────────
//
//	event                     | EMAIL | WS
//	--------------------------|-------|----
//	account.opened            |  ✅   | ✅
//	account.frozen            |  ✅   | ✅  critical
//	account.closed            |  ✅   | ✅
//	account.unfrozen          |  ✅   | ✅
//	account.deposit.matured   |  ✅   | ✅  important financial event
//	account.rdn.verified      |  ✅   | ✅
func MapAccountEvent(e AccountEvent, email string) []Notification {
	base := map[string]any{
		"user_code":      e.UserCode,
		"account_number": e.AccountNumber,
		"account_type":   e.AccountType,
		"occurred_at":    e.OccurredAt.Format("02 Jan 2006 15:04 WIB"),
	}

	var notifications []Notification

	switch e.EventType {

	case AccountOpened:
		notifications = append(notifications,
			wsNotif(e.UserCode, fmt.Sprintf("Rekening %s berhasil dibuka", e.AccountNumber), "account_opened", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("Rekening %s Berhasil Dibuka", e.AccountNumber), "account_opened", base),
			)
		}

	case AccountFrozen:
		notifications = append(notifications,
			wsNotif(e.UserCode, fmt.Sprintf("Rekening %s telah dibekukan", e.AccountNumber), "account_frozen", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("❄️ Rekening %s Dibekukan", e.AccountNumber), "account_frozen", base),
			)
		}

	case AccountClosed:
		notifications = append(notifications,
			wsNotif(e.UserCode, fmt.Sprintf("Rekening %s telah ditutup", e.AccountNumber), "account_closed", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("Rekening %s Telah Ditutup", e.AccountNumber), "account_closed", base),
			)
		}

	case AccountUnfrozen:
		notifications = append(notifications,
			wsNotif(e.UserCode, fmt.Sprintf("Rekening %s telah diaktifkan kembali", e.AccountNumber), "account_unfrozen", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("✅ Rekening %s Diaktifkan Kembali", e.AccountNumber), "account_unfrozen", base),
			)
		}

	case DepositMatured:
		notifications = append(notifications,
			wsNotif(e.UserCode, fmt.Sprintf("Deposito rekening %s telah jatuh tempo", e.AccountNumber), "deposit_matured", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("💰 Deposito Rekening %s Telah Jatuh Tempo", e.AccountNumber), "deposit_matured", base),
			)
		}

	case RdnVerified:
		notifications = append(notifications,
			wsNotif(e.UserCode, fmt.Sprintf("Rekening RDN %s terverifikasi", e.AccountNumber), "rdn_verified", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("✅ Rekening RDN %s Terverifikasi", e.AccountNumber), "rdn_verified", base),
			)
		}
	}

	return notifications
}

// ── Transfer Event Mapper ─────────────────────────────────────────────────────
//
// Transfer selalu dikirim ke BOTH channel — email sebagai bukti transaksi resmi,
// WS sebagai real-time balance update.
func MapTransferEvent(e StructuredTransferEvent, email string) []Notification {
	base := map[string]any{
		"user_code":             e.Data.UserCode,
		"reference_id":          e.Data.ReferenceID,
		"source_account_number": e.Data.SourceAccountNumber,
		"target_account_number": e.Data.TargetAccountNumber,
		"amount":                e.Data.Amount.String(),
		"currency":              e.Data.Currency,
		"note":                  e.Data.Note,
		"timestamp":             e.Timestamp.Format("02 Jan 2006 15:04 WIB"),
		"type":                  string(e.Type),
	}

	var notifications []Notification

	switch e.Type {
	case NotificationTransferConfirmed:
		notifications = append(notifications,
			wsNotif(e.Data.UserCode, "Transfer berhasil dikonfirmasi", "transfer_confirmed", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("✅ Bukti Transfer - Ref: %s", e.Data.ReferenceID), "transfer_confirmed", base),
			)
		}

	case NotificationTopUpSuccess:
		notifications = append(notifications,
			wsNotif(e.Data.UserCode, "Top-up berhasil", "top_up_success", base),
		)
		if email != "" {
			notifications = append(notifications,
				emailNotif(email, fmt.Sprintf("💳 Top-up Berhasil - Ref: %s", e.Data.ReferenceID), "top_up_success", base),
			)
		}
	}

	return notifications
}

// ── MapFlatTransferEvent — mapper untuk format flat TransferEvent ─────────────
// Digunakan jika Kafka topic transfer.events mengirim format flat (bukan StructuredTransferEvent).
func MapFlatTransferEvent(e TransferEvent, userCode string, email string) []Notification {
	base := map[string]any{
		"user_code":             userCode,
		"reference_id":          e.ReferenceID,
		"source_account_number": e.SourceAccountNumber,
		"target_account_number": e.TargetAccountNumber,
		"amount":                e.Amount.String(),
		"currency":              e.Currency,
		"timestamp":             e.OccurredAt.Format("02 Jan 2006 15:04 WIB"),
	}

	var notifications []Notification
	notifications = append(notifications,
		wsNotif(userCode, "Transfer berhasil dikonfirmasi", "transfer_confirmed", base),
	)
	if email != "" {
		notifications = append(notifications,
			emailNotif(email, fmt.Sprintf("✅ Bukti Transfer - Ref: %s", e.ReferenceID), "transfer_confirmed", base),
		)
	}
	return notifications
}

// ── helpers ───────────────────────────────────────────────────────────────────

func wsNotif(userCode, subject, template string, data map[string]any) Notification {
	return Notification{
		To:       userCode,
		Subject:  subject,
		Channel:  ChannelWS,
		Template: template,
		Data:     data,
	}
}

func emailNotif(emailAddr, subject, template string, data map[string]any) Notification {
	return Notification{
		To:       emailAddr,
		Subject:  subject,
		Channel:  ChannelEmail,
		Template: template,
		Data:     data,
	}
}
