# Laporan Hasil Pengujian Keamanan Sistem Informasi (KSI)

Dokumen ini mencatat bukti hasil pengujian nyata terhadap kedua versi aplikasi (Versi Rentan Port 3001 vs Versi Aman Port 3002).

**Waktu Pengujian:** Selasa, 13 Oktober 2026  
**Metode:** Pengujian Otomatis (*Automated End-to-End Test Suite* via `node test-security.js`) & Verifikasi Respon HTTP Langsung.  
**Lingkungan:** Localhost (Node.js v24.14.0, SQLite In-Process).

---

## 1. Rekapitulasi Hasil Pengujian

| No | Modul / Kerentanan | Status Versi Rentan (`rentan/`) | Status Versi Aman (`aman/`) | Kesimpulan Kontrol |
|:---:|---|:---:|:---:|:---:|
| 1 | **SQL Injection (Login Bypass)** | ❌ TERBUKTI RENTAN (HTTP 302 Bypass Sukses) | ✅ TERBUKTI AMAN (HTTP 302 Error, Prepared Statement) | Efektif |
| 2 | **IDOR (Transkrip Nilai Mahasiswa)** | ❌ TERBUKTI RENTAN (Data Mahasiswa Lain Bocor) | ✅ TERBUKTI AMAN (Otorisasi Sisi Server Aktif) | Efektif |
| 3 | **Stored XSS (Forum Diskusi)** | ❌ TERBUKTI RENTAN (Tag `<script>` Dieksekusi) | ✅ TERBUKTI AMAN (HTML Entity Encoding & CSP) | Efektif |
| 4 | **Login Brute-Force & Rate Limiting** | ❌ TERBUKTI RENTAN (Tanpa Batas Percobaan) | ✅ TERBUKTI AMAN (HTTP 429 Lockout Percobaan ke-6) | Efektif |
| 5 | **Broken Access Control (Panel Admin)** | ❌ TERBUKTI RENTAN (Mahasiswa Dapat Buka Admin) | ✅ TERBUKTI AMAN (HTTP 403 Forbidden via RBAC) | Efektif |

---

## 2. Rincian Pengujian per Kerentanan

### Pengujian 1: SQL Injection pada Form Login
- **Payload:** `username=' OR '1'='1' --&password=apapun`
- **Hasil Versi Rentan (`port 3001`):**
  - Query yang dieksekusi: `SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = 'apapun' AND is_active = 1`
  - Respon HTTP: `302 Found`, Header `Location: /`
  - Header Cookie: `set-cookie: user_id=1` (Login otomatis sebagai user pertama).
  - *Status:* **VULNERABLE (Bypass Berhasil)**.
- **Hasil Versi Aman (`port 3002`):**
  - Parameter dipisahkan melalui Prepared Statement (`?`). String input diperlakukan sebagai literal nama pengguna, bukan sintaks SQL.
  - Respon HTTP: `302 Found`, Header `Location: /login?error=Kredensial+tidak+valid.+Sisa+percobaan:+4`
  - *Status:* **SECURE (Serangan Dinetralkan)**.

---

### Pengujian 2: Insecure Direct Object References (IDOR)
- **Metode Pengujian:** Pengguna masuk sebagai `mhs_budi` (User ID: 1), lalu mengirimkan permintaan `GET /grades?student_id=2`.
- **Hasil Versi Rentan (`port 3001`):**
  - Server mengambil parameter mentah `student_id = 2`.
  - Body respon mengandung: `"Siti Rahmawati"`, `"NIM: 20240102"`, nilai mata kuliah milik Siti (`BASDAT101`).
  - *Status:* **VULNERABLE (Pelanggaran Privasi / Kebocoran Data Mahasiswa Lain)**.
- **Hasil Versi Aman (`port 3002`):**
  - Server memeriksa peran pengguna. Karena peran adalah `mahasiswa`, parameter `student_id` dari query string diabaikan, dan server memaksakan pembacaan nilai dari `req.user.id` (ID: 1).
  - Body respon HANYA memuat data milik `"Budi Wicaksono"` (NIM: 20240101).
  - *Status:* **SECURE (Otorisasi Berbasis Sesi Ditegakkan)**.

---

### Pengujian 3: Stored Cross-Site Scripting (Stored XSS)
- **Payload:** `<script>alert("XSS_KSI_VERIFIED")</script>`
- **Hasil Versi Rentan (`port 3001`):**
  - Dikirim melalui formulir diskusi `POST /forum`.
  - Data disimpan mentah ke basis data dan dirender langsung ke browser tanpa escaping.
  - Halaman `GET /forum` memuat string tag mentah: `<script>alert("XSS_KSI_VERIFIED")</script>`.
  - Pada browser, skrip langsung tereksekusi.
  - *Status:* **VULNERABLE (Eksekusi Skrip Tak Terotorisasi)**.
- **Hasil Versi Aman (`port 3002`):**
  - Payload dikirim dengan token CSRF yang sah.
  - Saat dirender kembali oleh server, karakter berbahaya dienkode menjadi:
    `&lt;script&gt;alert(&quot;XSS_KSI_VERIFIED&quot;)&lt;/script&gt;`
  - Tag mentah `<script>` tidak ada di dalam dokumen.
  - Dilengkapi header respons `Content-Security-Policy: default-src 'self'`.
  - *Status:* **SECURE (HTML Encoding & CSP Mencegah Eksekusi)**.

---

### Pengujian 4: Brute Force & Rate Limiting
- **Metode Pengujian:** Mengirimkan 7 kali permintaan login gagal berturut-turut untuk akun `mhs_budi` dengan password salah.
- **Hasil Versi Rentan (`port 3001`):**
  - Seluruh 7 permintaan diproses tanpa penundaan dan tanpa pemblokiran (Semua mengembalikan status 302 ke formulir login tanpa batas).
  - *Status:* **VULNERABLE (Rentan Serangan Kamus & Otomatisasi Tebakan Password)**.
- **Hasil Versi Aman (`port 3002`):**
  - Percobaan 1 s/d 5 dicatat sebagai kegagalan dan sisa kuota percobaan ditampilkan.
  - Pada percobaan ke-6, Rate Limiter memicu pembekuan (*lockout*).
  - Respon HTTP: **`429 Too Many Requests`**.
  - Pesan Respon: *"Akun / IP Sementara Dibekukan ... silakan tunggu 300 detik"*.
  - Log dicatat pada tabel `login_logs` di database.
  - *Status:* **SECURE (Rate Limiting & Akun Lockout Bekerja Sesuai Kebijakan)**.

---

### Pengujian 5: Broken Access Control (Endpoint Administrator)
- **Metode Pengujian:** Mengakses URL `GET /admin/users` menggunakan sesi `mhs_budi` (Mahasiswa).
- **Hasil Versi Rentan (`port 3001`):**
  - Respon HTTP: `200 OK`.
  - Halaman manajemen akun pengguna terbuka dan dapat dilihat oleh mahasiswa.
  - *Status:* **VULNERABLE (Missing Functional-Level Access Control)**.
- **Hasil Versi Aman (`port 3002`):**
  - Respon HTTP: **`403 Forbidden`**.
  - Pesan Respon: *"Akses Ditolak: Peran akun Anda (mahasiswa) tidak memiliki izin"*.
  - *Status:* **SECURE (RBAC Middleware Melindungi Sumber Daya Administratif)**.

---

## 3. Status Tangkapan Layar (Screenshot Evidence)

- **Pengujian Logika Backend & HTTP:** Telah diverifikasi 100% menggunakan test harness otomatis (`test-security.js`).
- **Tangkapan Layar GUI Browser:**
  - `bukti/rentan/`: *Tersedia placeholder `.gitkeep`. Praktikan dapat melampirkan screenshot antarmuka grafis browser saat membuka masing-masing skenario.*
  - `bukti/aman/`: *Tersedia placeholder `.gitkeep`. Praktikan dapat melampirkan screenshot antarmuka grafis browser saat kontrol keamanan aktif.*
  - *Catatan Kepatuhan:* Sesuai instruksi praktikum, tangkapan layar GUI browser tidak dikarang dan disiapkan untuk diisi langsung oleh praktikan saat presentasi/laporan akhir.
