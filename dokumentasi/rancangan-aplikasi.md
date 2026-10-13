# Rancangan Arsitektur Aplikasi Portal Kampus "SIAKAD Nusantara"

**Mata Kuliah:** Keamanan Sistem Informasi (KSI)  
**Proyek:** Laboratorium Pengujian Keamanan Aplikasi Web (Versi Rentan vs Versi Aman)  
**Institusi Fiktif:** Institut Teknologi & Sains Nusantara (ITSN)

---

## 1. Ringkasan Eksekutif & Tujuan

Proyek ini dirancang sebagai laboratorium komparatif untuk mempelajari mekanisme serangan berbasis web dan implementasi kontrol pertahanan yang sesuai. Sistem dibangun dengan dua instans web terpisah yang memiliki fungsionalitas bisnis serupa:

1. **Versi Rentan (`rentan/` - Port 3001):** Mengandung kerentanan umum web aplikasi (OWASP Top 10) seperti SQL Injection, IDOR, Stored XSS, Broken Access Control, dan ketiadaan perlindungan brute force.
2. **Versi Aman (`aman/` - Port 3002):** Telah diperkuat (*hardened*) menggunakan kontrol keamanan defensif standar, mencakup *Prepared Statements*, *Role-Based Access Control (RBAC)* sisi server, *contextual output encoding*, *Content Security Policy (CSP)*, *cryptographic session management*, *Bcrypt password hashing*, *CSRF token*, dan *rate limiting / account lockout*.

---

## 2. Pemilihan Teknologi & Lingkungan Eksekusi

Aplikasi dirancang agar sepenuhnya mandiri (*self-contained*), ringan, dan dapat berjalan langsung pada lingkungan lokal praktikan:

- **Runtime:** Node.js (v24.x LTS)
- **Web Framework:** Express.js (v5.x)
- **Mesin Basis Data:** `node:sqlite` (Mesin SQLite bawaan Node.js, berjalan secara in-process tanpa perlu menginstal atau menyalakan servis MySQL/XAMPP eksternal).
- **Isolasi Database:**
  - `database/rentan.sqlite` untuk versi rentan (password tersimpan plaintext untuk demonstrasi SQLi).
  - `database/aman.sqlite` untuk versi aman (password tersimpan menggunakan hash Bcrypt).
- **Pustaka Pendukung:**
  - `bcryptjs`: Algoritma hashing kata sandi aman.
  - `cookie-parser`: Penanganan cookie sesi.
  - `multer`: Pengunggahan berkas tugas mahasiswa.

---

## 3. Matriks Peran & Hak Akses (Role-Based Access Control)

Sistem membedakan tiga peran pengguna fiktif:

| Fitur / Modul | Mahasiswa | Dosen | Administrator | Catatan Kontrol |
|---|:---:|:---:|:---:|---|
| Login & Logout | Ya | Ya | Ya | Sesi terisolasi |
| Melihat Nilai Pribadi | Ya | Tidak | Tidak | Aman: Terikat ID sesi. Rentan: IDOR parameter |
| Rekap Nilai Mahasiswa | Tidak | Ya | Ya | Hanya Dosen & Admin |
| Mengunggah Tugas | Ya | Tidak | Tidak | Aman: Pembatasan ekstensi & MIME |
| Menilai Tugas | Tidak | Ya | Tidak | Dosen menginput skor & feedback |
| Forum Diskusi (Baca & Tulis) | Ya | Ya | Ya | Aman: HTML Encoding. Rentan: Stored XSS |
| Manajemen Akun Pengguna | Tidak | Tidak | Ya | Kelola user, reset status aktif |

---

## 4. Desain Skema Basis Data

Basis data terdiri dari 6 entitas tabel relasional:

1. **`users`**:
   - `id` (INTEGER PK AUTOINCREMENT)
   - `username` (VARCHAR(50) UNIQUE)
   - `password` (TEXT) - *Plaintext pada Rentan, Bcrypt pada Aman*
   - `full_name` (VARCHAR(100))
   - `role` (VARCHAR(20) CHECK: mahasiswa, dosen, admin)
   - `identity_number` (VARCHAR(30)) - *NIM / NIP / ID Pegawai*
   - `email` (VARCHAR(100))
   - `is_active` (INTEGER DEFAULT 1)
   - `created_at` (DATETIME)

2. **`courses`**:
   - `id` (INTEGER PK AUTOINCREMENT)
   - `code` (VARCHAR(15) UNIQUE)
   - `name` (VARCHAR(100))
   - `credits` (INTEGER)
   - `lecturer_id` (INTEGER FK -> users.id)

3. **`grades`**:
   - `id` (INTEGER PK AUTOINCREMENT)
   - `student_id` (INTEGER FK -> users.id)
   - `course_id` (INTEGER FK -> courses.id)
   - `assignment_score` (REAL)
   - `mid_score` (REAL)
   - `final_score` (REAL)
   - `letter_grade` (VARCHAR(2))
   - `updated_at` (DATETIME)

4. **`assignments`**:
   - `id` (INTEGER PK AUTOINCREMENT)
   - `student_id` (INTEGER FK -> users.id)
   - `course_id` (INTEGER FK -> courses.id)
   - `title` (VARCHAR(150))
   - `file_path` (VARCHAR(255))
   - `original_filename` (VARCHAR(255))
   - `submitted_at` (DATETIME)
   - `score` (REAL DEFAULT NULL)
   - `feedback` (TEXT DEFAULT NULL)

5. **`forum_posts`**:
   - `id` (INTEGER PK AUTOINCREMENT)
   - `user_id` (INTEGER FK -> users.id)
   - `title` (VARCHAR(150))
   - `content` (TEXT)
   - `created_at` (DATETIME)

6. **`login_logs`**:
   - `id` (INTEGER PK AUTOINCREMENT)
   - `ip_address` (VARCHAR(45))
   - `username` (VARCHAR(50))
   - `status` (VARCHAR(20))
   - `attempt_time` (DATETIME)

---

## 5. Akun Pengujian Fiktif (Synthetic Test Accounts)

| Peran | Username | Password | Nama Lengkap | Identitas |
|---|---|---|---|---|
| Mahasiswa 1 | `mhs_budi` | `BudiPass123!` | Budi Wicaksono | NIM 20240101 |
| Mahasiswa 2 | `mhs_siti` | `SitiPass123!` | Siti Rahmawati | NIM 20240102 |
| Dosen | `dosen_hendra` | `DosenPass123!` | Dr. Hendra Pratama, M.Kom. | NIP 198502012010121001 |
| Admin | `admin_fajar` | `AdminPass123!` | Fajar Administrator | ID ADM001 |

*Catatan: Seluruh data di atas fiktif murni dan dibuat khusus untuk pengujian laboratorium.*
