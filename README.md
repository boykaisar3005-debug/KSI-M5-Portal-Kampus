# Laboratorium Praktikum Keamanan Sistem Informasi (KSI)
## Portal Akademik Fiktif "SIAKAD Nusantara" (Versi Rentan vs Versi Aman)

Proyek ini dibangun sebagai materi pembelajaran dan pengujian praktikum mata kuliah **Keamanan Sistem Informasi (KSI)**. Proyek ini mendemonstrasikan implementasi dua versi aplikasi web:
1. **Versi Rentan (`rentan/`):** Aplikasi sengaja dibuat memiliki celah keamanan umum berbasis web (OWASP Top 10) untuk latihan analisis dan eksploitasi di lingkungan lab lokal.
2. **Versi Aman (`aman/`):** Aplikasi dengan arsitektur dan fitur yang setara, namun telah diproteksi menggunakan kontrol keamanan (*hardening*) standar industri.

---

## ⚠️ Batasan Lingkungan & Kode Etik

- **HANYA UNTUK PRAKTIKUM LOKAL:** Seluruh kerentanan yang sengaja dibuat hanya diizinkan untuk diuji di lingkungan lokal (`localhost`) tertutup.
- **DILARANG MENYERANG SISTEM NYATA:** Teknik eksploitasi dalam proyek ini ditujukan murni untuk pemahaman akademis dan evaluasi defensif.
- **TIDAK ADA DATA ASLI:** Seluruh entitas, nama kampus, NIM, NIP, nilai, dan akun adalah data sintetis fiktif. Tidak mengandung kredensial atau data pribadi nyata.
- **ISOLASI BASIS DATA:** Versi rentan dan aman menggunakan file database SQLite terpisah (`rentan.sqlite` dan `aman.sqlite`), sehingga pengujian pada salah satu versi tidak akan merusak versi lainnya.

---

## 🛠️ Teknologi yang Digunakan

- **Runtime:** Node.js (v24.x LTS)
- **Framework Web:** Express.js (v5.x)
- **Database Engine:** `node:sqlite` (SQLite bawaan Node.js, tidak memerlukan instalasi MySQL/server terpisah)
- **Keamanan & Autentikasi:**
  - `bcryptjs` (Hashing password satu arah dengan garam)
  - `cookie-parser` (Pengelolaan cookie sesi terproteksi)
  - `crypto` bawaan Node.js (Pembangkit token acak untuk CSRF & ID sesi)
- **Manajemen Berkas:** `multer` (Validasi ekstensi, MIME type, dan ukuran berkas)

---

## 📂 Struktur Folder Proyek

```text
KSI M5/
├── .gitignore                      # Pengecualian berkas rahasia, log, dan node_modules
├── package.json                    # Konfigurasi dependensi dan skrip proyek
├── test-security.js                # Skrip pengujian otomatis (verifikasi kedua server)
├── README.md                       # Dokumentasi utama proyek
│
├── database/                       # Skema dan inisialisasi basis data
│   ├── schema.sql                  # Definisi tabel DDL (users, courses, grades, dll.)
│   ├── seed.sql                    # Data awal sintetis
│   ├── init-db.js                  # Skrip pembuat database rentan.sqlite & aman.sqlite
│   ├── rentan.sqlite               # Database terisolasi versi rentan
│   └── aman.sqlite                 # Database terisolasi versi aman
│
├── rentan/                         # Source code aplikasi versi RENTAN (Port 3001)
│   ├── server.js                   # Server Express dengan celah keamanan yang disengaja
│   ├── public/style.css            # Antarmuka bertema merah (Vulnerable)
│   └── uploads/                    # Folder penyimpanan berkas tugas
│
├── aman/                           # Source code aplikasi versi AMAN (Port 3002)
│   ├── server.js                   # Server Express dengan mitigasi keamanan lengkap
│   ├── public/style.css            # Antarmuka bertema hijau/teal (Hardened)
│   └── uploads/                    # Folder penyimpanan berkas tugas terproteksi
│
├── dokumentasi/                    # Laporan perancangan dan pengujian rinci
│   ├── rancangan-aplikasi.md       # Arsitektur sistem, RBAC, dan skema data
│   ├── daftar-kerentanan.md        # Rincian teknis CWE/OWASP dan perbaikannya
│   ├── skenario-pengujian.md       # Langkah reproduksi pengujian manual browser
│   └── hasil-pengujian.md          # Laporan verifikasi hasil uji nyata
│
└── bukti/                          # Tempat penyimpanan screenshot hasil pengujian
    ├── rentan/                     # Bukti pengujian pada versi rentan
    └── aman/                       # Bukti pengujian pada versi aman
```

---

## 👥 Akun Demonstrasi (Data Sintetis Fiktif)

Semua akun menggunakan kredensial sintetis lokal berikut:

| Peran | Username | Password | Nama Lengkap | Identitas |
|---|---|---|---|---|
| **Mahasiswa 1** | `mhs_budi` | `BudiPass123!` | Budi Wicaksono | NIM: 20240101 |
| **Mahasiswa 2** | `mhs_siti` | `SitiPass123!` | Siti Rahmawati | NIM: 20240102 |
| **Dosen** | `dosen_hendra` | `DosenPass123!` | Dr. Hendra Pratama, M.Kom. | NIP: 198502012010121001 |
| **Admin** | `admin_fajar` | `AdminPass123!` | Fajar Administrator | ID: ADM001 |

---

## 🚀 Panduan Instalasi dan Menjalankan Aplikasi

### 1. Prasyarat
Pastikan Node.js (v20+ atau v24+) terpasang di komputer Anda.

### 2. Instalasi Dependensi
Buka terminal pada folder proyek:
```bash
cd "C:\Users\MyBook Hype AMD\Desktop\KSI M5"
npm install
```

### 3. Inisialisasi Basis Data Terisolasi
Jalankan perintah ini untuk membuat `rentan.sqlite` dan `aman.sqlite` dari awal:
```bash
npm run init-db
```

### 4. Menjalankan Aplikasi
Anda dapat menjalankan kedua server secara bersamaan pada jendela terminal terpisah untuk membandingkannya secara berdampingan:

- **Menjalankan Versi Rentan (Port 3001):**
  ```bash
  npm run start:rentan
  ```
  Akses di browser: `http://localhost:3001`

- **Menjalankan Versi Aman (Port 3002):**
  ```bash
  npm run start:aman
  ```
  Akses di browser: `http://localhost:3002`

### 5. Menjalankan Pengujian Otomatis
Untuk memverifikasi seluruh celah dan perbaikannya dalam satu perintah:
```bash
npm run test:security
```

---

## 🔍 Daftar Kerentanan & Kontrol Keamanan

| No | Nama Kerentanan | Kondisi Versi Rentan (`rentan/`) | Kontrol pada Versi Aman (`aman/`) |
|:---:|---|---|---|
| 1 | **SQL Injection (SQLi)** | String concatenation langsung pada klausa query login & pencarian nilai. Bypass via `' OR '1'='1' --`. | Prepared statements (`?`), pemisahan token SQL dari literal data pengguna. |
| 2 | **IDOR (Insecure Direct Object References)** | Menerima parameter `student_id` dari query string tanpa validasi kepemilikan. Budi bisa melihat nilai Siti via `?student_id=2`. | Validasi otorisasi server-side; mahasiswa dipaksa membaca nilai miliknya sendiri (`req.user.id`). |
| 3 | **Stored Cross-Site Scripting (Stored XSS)** | Konten forum disimpan dan dirender mentah tanpa encoding. Script jahat `<script>alert(1)</script>` langsung dieksekusi browser. | Contextual HTML Entity Encoding (`escapeHtml`) dan Content-Security-Policy (CSP) HTTP headers. |
| 4 | **No Rate Limiting / Brute Force** | Form login mengizinkan percobaan tebakan password ribuan kali tanpa batas atau delay. | In-memory rate limiting (maksimal 5 kali kegagalan, pembekuan 5 menit / HTTP 429), pencatatan ke tabel `login_logs`. |
| 5 | **Broken Access Control & Session** | Cookie tanpa tanda tangan (`httpOnly: false`), URL Admin (`/admin/users`) dapat dibuka mahasiswa. | Role-Based Access Control (RBAC) middleware ketat (HTTP 403), Session Regeneration kriptografis, Cookie `httpOnly`, CSRF Token. |

---

## 📸 Panduan Pengambilan Bukti Tangkapan Layar (Screenshot)

Untuk keperluan laporan praktikum, ambil screenshot pada momen-momen berikut:
1. **Bukti SQLi:**
   - Rentan: Screenshot halaman dashboard berhasil terbuka saat login dengan `' OR '1'='1' --`. Simpan ke `bukti/rentan/1-sqli-login-rentan.png`.
   - Aman: Screenshot pesan error penolakan kredensial. Simpan ke `bukti/aman/1-sqli-login-aman.png`.
2. **Bukti IDOR:**
   - Rentan: Buka URL `http://localhost:3001/grades?student_id=2` dengan akun Budi (menampilkan data Siti). Simpan ke `bukti/rentan/2-idor-nilai-rentan.png`.
   - Aman: Buka URL yang sama di port 3002 (hanya menampilkan nilai Budi). Simpan ke `bukti/aman/2-idor-nilai-aman.png`.
3. **Bukti Stored XSS:**
   - Rentan: Screenshot pop-up dialog `alert()` di forum. Simpan ke `bukti/rentan/3-xss-forum-rentan.png`.
   - Aman: Screenshot teks script yang tampil sebagai teks biasa yang aman. Simpan ke `bukti/aman/3-xss-forum-aman.png`.
4. **Bukti Brute Force:**
   - Rentan: Screenshot multiple invalid login tanpa halangan. Simpan ke `bukti/rentan/4-bruteforce-rentan.png`.
   - Aman: Screenshot halaman blokir HTTP 429 "Akun / IP Sementara Dibekukan". Simpan ke `bukti/aman/4-bruteforce-aman.png`.

---

## 🛡️ Kesiapan Repositori Publik (GitHub)

Proyek ini telah dikonfigurasi dengan `.gitignore` yang bersih:
- `node_modules/` dan temporary logs dikecualikan.
- Tidak ada token privat, API key, atau kredensial nyata yang tersimpan di dalam repositori.
- Data sintetis aman untuk diunggah ke repositori publik saat diinstruksikan.
