**Hampir benar**, tapi urutannya perlu disesuaikan:

```
POST /api/auth/register         → daftar, status = PENDING_VERIFICATION

GET  /api/auth/verify-email     → klik link di email, status = ACTIVE
                                  (tanpa ini user tidak bisa login)

POST /api/auth/mfa/setup        → generate secret + return QR code
                                  (butuh login dulu untuk tau siapa usernya)

POST /api/auth/mfa/setup/verify → konfirmasi OTP pertama kali
                                  → mfa_enabled = true
                                  (memastikan user berhasil scan QR)

POST /api/auth/login            → email + password → dapat mfaToken

POST /api/auth/mfa/verify       → input OTP → dapat accessToken + refreshToken

Endpoint lain                   → pakai accessToken
```

---

**Yang berbeda dari yang kamu tulis:**

`verify-email` harus ada sebelum bisa login — kalau tidak, user `PENDING_VERIFICATION` langsung ditolak di login karena status bukan `ACTIVE`.

`mfa/setup` harus sebelum `login` pertama kali — karena saat login sudah langsung minta OTP, kalau secret belum ada ya tidak bisa verify.

`mfa/setup/verify` terpisah dari `mfa/setup` — setup hanya return QR, verify konfirmasi user berhasil scan dan OTP-nya valid.

---

Mau mulai dari endpoint mana dulu? Gw saranin urutan:
1. `verify-email` dulu karena blocking semua flow lainnya
2. `mfa/setup` + `mfa/setup/verify`
3. Baru `login` → `mfa/verify` yang udah kita buat 🚀