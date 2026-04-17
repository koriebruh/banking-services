package notification

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"strings"

	"golang-clean-architecture/internal/event"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// EmailSender menangani pengiriman email via SMTP.
// Kompatibel dengan MailHog (anonymous, non-TLS) dan SMTP sungguhan (dengan auth).
type EmailSender struct {
	log      *logrus.Logger
	host     string
	port     int
	from     string
	username string
	password string
}

// NewEmailSender membuat EmailSender dari konfigurasi viper.
//
// Kenapa tidak pakai smtp.PlainAuth langsung?
// Go's smtp.PlainAuth menolak mengirim credentials ke server non-localhost
// melalui koneksi non-TLS (error: "unencrypted connection"), meskipun server
// (MailHog) menerima PLAIN auth tanpa TLS. Solusinya: dial manual via net.Conn
// dan kirim AUTH PLAIN secara eksplisit tanpa restriction Go stdlib.
func NewEmailSender(cfg *viper.Viper, log *logrus.Logger) *EmailSender {
	host := cfg.GetString("smtp.host")
	port := cfg.GetInt("smtp.port")
	from := cfg.GetString("smtp.from")
	username := cfg.GetString("smtp.username")
	password := cfg.GetString("smtp.password")

	log.Infof("[email] SMTP configured: host=%s port=%d from=%s useAuth=%v",
		host, port, from, username != "")

	return &EmailSender{
		log:      log,
		host:     host,
		port:     port,
		from:     from,
		username: username,
		password: password,
	}
}

// Send mengirim satu notifikasi email.
func (s *EmailSender) Send(n event.Notification) error {
	if n.Channel != event.ChannelEmail {
		return fmt.Errorf("email_sender: channel bukan EMAIL, got %s", n.Channel)
	}

	body, err := renderTemplate(n.Template, n.Data)
	if err != nil {
		s.log.Errorf("[email] gagal render template `%s`: %v", n.Template, err)
		return err
	}

	msg := buildMIMEMessage(s.from, n.To, n.Subject, body)

	if err := s.sendViaSMTP(n.To, msg); err != nil {
		s.log.Errorf("[email] gagal kirim ke %s: %v", n.To, err)
		return err
	}

	s.log.Infof("[email] terkirim ke=%s subject=%q template=%s", n.To, n.Subject, n.Template)
	return nil
}

// sendViaSMTP melakukan koneksi raw ke SMTP server dan mengirim email.
// Menggunakan net.Dial (bukan TLS) sehingga compatible dengan MailHog.
// Auth PLAIN dikirim manual jika username tersedia, tanpa TLS-check dari stdlib.
func (s *EmailSender) sendViaSMTP(to string, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	// Dial TCP biasa (non-TLS) — MailHog tidak butuh TLS
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	// Buat smtp.Client dari koneksi raw
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("smtp.NewClient: %w", err)
	}
	defer client.Quit() //nolint:errcheck

	// Auth PLAIN — hanya jika credentials tersedia.
	// Kita kirim manual tanpa melewati TLS-check bawaan smtp.PlainAuth.
	if s.username != "" && s.password != "" {
		if err := client.Auth(plainAuthUnsafe(s.username, s.password)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close data writer: %w", err)
	}

	return nil
}

// plainAuthUnsafe adalah implementasi smtp.Auth yang identik dengan smtp.PlainAuth
// namun TANPA TLS-check. Digunakan untuk MailHog dan SMTP server internal
// yang menerima PLAIN auth tanpa TLS (misalnya dalam docker network).
//
// JANGAN gunakan ini untuk SMTP publik (Gmail, Outlook, dll) — gunakan TLS/STARTTLS.
type plainAuthUnsafeImpl struct {
	username, password string
}

func plainAuthUnsafe(username, password string) smtp.Auth {
	return &plainAuthUnsafeImpl{username: username, password: password}
}

func (a *plainAuthUnsafeImpl) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	// Format: \0username\0password
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (a *plainAuthUnsafeImpl) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, fmt.Errorf("unexpected server challenge")
	}
	return nil, nil
}

// buildMIMEMessage menyusun raw MIME email dengan Content-Type text/html.
func buildMIMEMessage(from, to, subject, htmlBody string) []byte {
	var sb strings.Builder
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	sb.WriteString(fmt.Sprintf("From: %s\r\n", from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", to))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	sb.WriteString("\r\n")
	sb.WriteString(htmlBody)
	return []byte(sb.String())
}

// renderTemplate merender HTML email dari nama template + data dinamis.
func renderTemplate(templateName string, data map[string]any) (string, error) {
	tmplStr, ok := emailTemplates[templateName]
	if !ok {
		tmplStr = emailTemplates["_default"]
	}

	tmpl, err := template.New(templateName).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template error: %w", err)
	}
	return buf.String(), nil
}

// ── HTML Templates ────────────────────────────────────────────────────────────
// Inline templates. Data key mengikuti mapper.go.

var emailTemplates = map[string]string{

	// ── Default / Fallback ────────────────────────────────
	"_default": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#1a1a2e;margin-top:0}.info{color:#555;font-size:14px;line-height:1.6}
.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<h2>Notifikasi Banking Service</h2>
<div class="info"><p>Halo, ada notifikasi baru untuk akun Anda.</p>
{{range $k,$v := .}}<p><strong>{{$k}}</strong>: {{$v}}</p>{{end}}</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	// ── Auth Events ───────────────────────────────────────
	"user_registered": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">✅ Registrasi Berhasil</span>
<h2>Selamat Datang di Banking Service!</h2>
<div class="info">
<p>Akun Anda telah berhasil dibuat.</p>
<p><strong>User Code:</strong> {{.user_code}}</p>
<p><strong>Tanggal:</strong> {{.occurred_at}}</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"login_failed": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#d62828;margin-top:0}.badge{display:inline-block;background:#ffe8e8;color:#d62828;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">⚠️ Peringatan Keamanan</span>
<h2>Percobaan Login Gagal Terdeteksi</h2>
<div class="info">
<p>Terdeteksi percobaan login yang gagal pada akun Anda.</p>
<p><strong>User Code:</strong> {{.user_code}}</p>
<p><strong>IP Address:</strong> {{.ip_address}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
<p>Jika ini bukan Anda, segera ubah password Anda.</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"password_changed": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#1a1a2e;margin-top:0}.badge{display:inline-block;background:#e8f4fd;color:#1a73e8;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">🔒 Keamanan Akun</span>
<h2>Password Anda Telah Diubah</h2>
<div class="info">
<p><strong>User Code:</strong> {{.user_code}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
<p>Jika Anda tidak melakukan perubahan ini, segera hubungi customer service.</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"password_reset": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#1a1a2e;margin-top:0}.badge{display:inline-block;background:#e8f4fd;color:#1a73e8;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">🔑 Reset Password</span>
<h2>Password Anda Telah Direset</h2>
<div class="info">
<p><strong>User Code:</strong> {{.user_code}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
<p>Jika Anda tidak meminta reset password, segera hubungi customer service.</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"mfa_enabled": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">🔐 Keamanan Ditingkatkan</span>
<h2>Two-Factor Authentication Diaktifkan</h2>
<div class="info">
<p><strong>User Code:</strong> {{.user_code}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
<p>Akun Anda sekarang lebih aman dengan autentikasi dua faktor.</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"account_locked": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#d62828;margin-top:0}.badge{display:inline-block;background:#ffe8e8;color:#d62828;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">🚨 Akun Dikunci</span>
<h2>Akun Anda Telah Dikunci</h2>
<div class="info">
<p><strong>User Code:</strong> {{.user_code}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
<p>Hubungi customer service untuk membuka kunci akun Anda.</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	// ── Account Events ────────────────────────────────────
	"account_opened": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">✅ Rekening Dibuka</span>
<h2>Rekening Berhasil Dibuka</h2>
<div class="info">
<p><strong>Nomor Rekening:</strong> {{.account_number}}</p>
<p><strong>Tipe Rekening:</strong> {{.account_type}}</p>
<p><strong>Tanggal:</strong> {{.occurred_at}}</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"account_frozen": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#d62828;margin-top:0}.badge{display:inline-block;background:#ffe8e8;color:#d62828;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">❄️ Rekening Dibekukan</span>
<h2>Rekening Anda Telah Dibekukan</h2>
<div class="info">
<p><strong>Nomor Rekening:</strong> {{.account_number}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
<p>Hubungi customer service untuk informasi lebih lanjut.</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"account_closed": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#1a1a2e;margin-top:0}.badge{display:inline-block;background:#f0f0f0;color:#555;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">Rekening Ditutup</span>
<h2>Rekening Anda Telah Ditutup</h2>
<div class="info">
<p><strong>Nomor Rekening:</strong> {{.account_number}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"account_unfrozen": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">✅ Rekening Aktif Kembali</span>
<h2>Rekening Anda Telah Diaktifkan Kembali</h2>
<div class="info">
<p><strong>Nomor Rekening:</strong> {{.account_number}}</p>
<p><strong>Waktu:</strong> {{.occurred_at}}</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"deposit_matured": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">💰 Deposito Jatuh Tempo</span>
<h2>Deposito Anda Telah Jatuh Tempo</h2>
<div class="info">
<p><strong>Nomor Rekening:</strong> {{.account_number}}</p>
<p><strong>Tipe:</strong> {{.account_type}}</p>
<p><strong>Tanggal:</strong> {{.occurred_at}}</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"rdn_verified": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">✅ RDN Terverifikasi</span>
<h2>Rekening Dana Nasabah Terverifikasi</h2>
<div class="info">
<p><strong>Nomor Rekening:</strong> {{.account_number}}</p>
<p><strong>Tanggal:</strong> {{.occurred_at}}</p>
</div>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	// ── Transfer Events ───────────────────────────────────
	"transfer_confirmed": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.info{color:#555;font-size:14px;line-height:1.8}
.amount{font-size:22px;font-weight:bold;color:#1a1a2e;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
td{padding:6px 4px;border-bottom:1px solid #eee;color:#555}
td:first-child{color:#999;width:45%}
.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">✅ Transfer Berhasil</span>
<h2>Bukti Transfer</h2>
<div class="amount">{{.currency}} {{.amount}}</div>
<table>
<tr><td>Reference ID</td><td>{{.reference_id}}</td></tr>
<tr><td>Dari Rekening</td><td>{{.source_account_number}}</td></tr>
<tr><td>Ke Rekening</td><td>{{.target_account_number}}</td></tr>
<tr><td>Keterangan</td><td>{{.note}}</td></tr>
<tr><td>Tanggal</td><td>{{.timestamp}}</td></tr>
</table>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,

	"top_up_success": `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:480px;margin:auto;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h2{color:#2d6a4f;margin-top:0}.badge{display:inline-block;background:#d8f3dc;color:#2d6a4f;padding:4px 10px;border-radius:12px;font-size:13px}
.amount{font-size:22px;font-weight:bold;color:#1a1a2e;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
td{padding:6px 4px;border-bottom:1px solid #eee;color:#555}
td:first-child{color:#999;width:45%}
.footer{color:#999;font-size:12px;margin-top:20px}</style></head>
<body><div class="card">
<span class="badge">💳 Top-up Berhasil</span>
<h2>Konfirmasi Top-up</h2>
<div class="amount">{{.currency}} {{.amount}}</div>
<table>
<tr><td>Reference ID</td><td>{{.reference_id}}</td></tr>
<tr><td>Ke Rekening</td><td>{{.target_account_number}}</td></tr>
<tr><td>Tanggal</td><td>{{.timestamp}}</td></tr>
</table>
<div class="footer">Email ini dikirim otomatis. Jangan balas email ini.</div>
</div></body></html>`,
}
