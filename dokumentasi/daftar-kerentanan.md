# Daftar Kerentanan dan Kontrol Keamanan (Vulnerability Catalogue)

Dokumen ini menjelaskan secara teknis kerentanan yang sengaja diimplementasikan pada versi `rentan` serta kontrol keamanan yang diterapkan pada versi `aman`.

---

## 1. SQL Injection (SQLi) - Authentication Bypass & Data Exposure

- **Klasifikasi:** OWASP Top 10 A03:2021 – Injection | CWE-89
- **Lokasi Kode Rentan:** `rentan/server.js` (Endpoint `POST /login` & `GET /grades`)
- **Mekanisme Celah:**
  Aplikasi menggabungkan (*concatenation*) string input pengguna secara mentah ke dalam klausa SQL:
  ```javascript
  // Kode Rentan:
  const rawQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}' AND is_active = 1`;
  const user = db.prepare(rawQuery).get();
  ```
- **Dampak Keamanan:**
  Attacker dapat melewati proses autentikasi tanpa mengetahui kata sandi yang sah menggunakan string manipulasi logika SQL seperti `' OR '1'='1' --`. Hal ini merusak aspek **Kerahasiaan (*Confidentiality*)** dan **Otentikasi**.
- **Solusi & Mitigasi pada Versi Aman (`aman/server.js`):**
  Menggunakan *Prepared Statement* dengan parameter terikat (*parameterized query*). Engine database memperlakukan input pengguna secara ketat sebagai literal data, bukan token instruksi SQL:
  ```javascript
  // Kode Aman:
  const stmt = db.prepare(`SELECT * FROM users WHERE username = ? AND is_active = 1`);
  const user = stmt.get(username);
  ```

---

## 2. Insecure Direct Object References (IDOR) - Horizontal Privilege Escalation

- **Klasifikasi:** OWASP Top 10 A01:2021 – Broken Access Control | CWE-639
- **Lokasi Kode Rentan:** `rentan/server.js` (Endpoint `GET /grades`)
- **Mekanisme Celah:**
  Aplikasi mempercayai parameter objek yang dikirim oleh klien melalui query string tanpa memverifikasi relasi otorisasi antara pemilik sesi dengan target objek:
  ```javascript
  // Kode Rentan:
  const studentId = req.query.student_id || user.id;
  // Menampilkan data studentId apapun yang diminta tanpa memeriksa apakah user adalah pemiliknya
  ```
- **Dampak Keamanan:**
  Mahasiswa A (misal ID 1) dapat memanipulasi parameter URL menjadi `?student_id=2` untuk membaca nilai akademik rahasia milik Mahasiswa B. Pelanggaran berat terhadap aspek **Kerahasiaan (*Confidentiality*)**.
- **Solusi & Mitigasi pada Versi Aman (`aman/server.js`):**
  Menegakkan otorisasi berbasis peran dan sesi di sisi server (*Server-Side Authorization Enforcement*):
  ```javascript
  // Kode Aman:
  let targetStudentId = user.id;
  if (user.role === 'mahasiswa') {
    // Paksa ID target selalu mengambil ID dari sesi server yang terotentikasi
    targetStudentId = user.id;
  } else if (['dosen', 'admin'].includes(user.role)) {
    // Dosen/admin diizinkan melihat mahasiswa lain berdasarkan peran
    targetStudentId = parseInt(req.query.student_id, 10) || user.id;
  }
  ```

---

## 3. Stored Cross-Site Scripting (Stored XSS) - Forum Diskusi

- **Klasifikasi:** OWASP Top 10 A03:2021 – Injection | CWE-79
- **Lokasi Kode Rentan:** `rentan/server.js` (Endpoint `POST /forum` & `GET /forum`)
- **Mekanisme Celah:**
  Pesan forum disimpan ke basis data tanpa sanitasi, dan dirender langsung ke dalam struktur DOM HTML tanpa melalui proses *HTML entity encoding*:
  ```javascript
  // Kode Rentan:
  const postsHtml = posts.map(p => `
    <div class="post-content">${p.content}</div>
  `).join('');
  ```
- **Dampak Keamanan:**
  Attacker dapat menyisipkan muatan skrip jahat seperti `<script>alert(document.cookie)</script>` atau `<img src=x onerror=...>` yang tersimpan permanen di database. Skrip akan otomatis tereksekusi pada browser pengguna lain yang membuka halaman forum, membuka peluang pencurian token sesi, defacement, atau manipulasi antarmuka (*Integrity & Confidentiality*).
- **Solusi & Mitigasi pada Versi Aman (`aman/server.js`):**
  1. Melakukan *Contextual HTML Entity Encoding* pada setiap variabel sebelum dimasukkan ke dalam template HTML:
     ```javascript
     function escapeHtml(str) {
       return String(str)
         .replace(/&/g, '&amp;')
         .replace(/</g, '&lt;')
         .replace(/>/g, '&gt;')
         .replace(/"/g, '&quot;')
         .replace(/'/g, '&#39;');
     }
     ```
  2. Menerapkan header keamanan **Content-Security-Policy (CSP)** untuk membatasi eksekusi inline script tak terpercaya:
     ```javascript
     res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self';");
     ```

---

## 4. Percobaan Login Tanpa Pembatasan (No Rate Limiting / Brute-Force)

- **Klasifikasi:** OWASP Top 10 A07:2021 – Identification and Authentication Failures | CWE-307
- **Lokasi Kode Rentan:** `rentan/server.js` (Endpoint `POST /login`)
- **Mekanisme Celah:**
  Tidak ada batasan frekuensi pengiriman formulir kredensial, tidak ada penundaan respon (*delay*), dan tidak ada mekanisme penguncian (*account lockout*) saat terjadi kegagalan berulang.
- **Dampak Keamanan:**
  Attacker dapat menjalankan serangan kamus (*dictionary attack*) atau *credential stuffing* dengan ribuan tebakan password per menit hingga akun target berhasil ditembus.
- **Solusi & Mitigasi pada Versi Aman (`aman/server.js`):**
  1. Implementasi pelacak percobaan login (*Rate Limiter*) berbasis pasangan IP dan Nama Pengguna.
  2. Batas maksimal 5 kali kegagalan dalam kurun waktu 5 menit.
  3. Mengembalikan status HTTP **429 (Too Many Requests)** dan mengunci akun sementara selama 5 menit jika batas terlampaui.
  4. Pencatatan setiap upaya masuk ke tabel `login_logs` untuk keperluan audit keamanan.

---

## 5. Ringkasan Perbandingan Kontrol Keamanan

| Parameter Keamanan | Versi Rentan (`rentan/`) | Versi Aman (`aman/`) |
|---|---|---|
| **Penyusunan Query SQL** | String Concatenation | Prepared Statements (`?`) |
| **Penyimpanan Password** | Plaintext | Bcrypt Hashing (Salt 10 Rounds) |
| **Kontrol Akses Objek (Nilai)** | Parameter klien (`req.query`) | Otorisasi sesi server (`req.user.id`) |
| **Kontrol Akses Role (RBAC)** | Tidak ada pembatasan ketat | Middleware `requireRole()` ketat (HTTP 403) |
| **Sanitasi Output Forum** | Mentah (*Raw HTML*) | HTML Entity Encoding + CSP Header |
| **Proteksi Brute-Force** | Tidak terbatas | Lockout 5x gagal, HTTP 429 |
| **Proteksi CSRF** | Tidak ada token | Token CSRF acak per sesi formulir |
| **Manajemen Cookie Sesi** | Cookie polos (`httpOnly: false`) | Kriptografis acak, `httpOnly: true`, `sameSite: 'lax'` |
| **Unggah Berkas Tugas** | Ekstensi & MIME bebas | Whitelist berkas aman (PDF/DOCX), Limit 5MB |
