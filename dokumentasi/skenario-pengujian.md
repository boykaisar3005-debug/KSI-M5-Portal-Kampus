# Skenario Pengujian Keamanan Web (Test Scenarios)

Panduan ini berisi langkah reproduksi pengujian di lingkungan lokal untuk menguji kondisi sebelum perbaikan (*Vulnerable*) dan setelah perbaikan (*Hardened*).

---

## Persiapan Lingkungan Pengujian

1. Pastikan database telah diinisialisasi:
   ```bash
   npm run init-db
   ```
2. Jalankan kedua server di terminal terpisah:
   - Terminal 1 (Versi Rentan): `npm run start:rentan` (berjalan di `http://localhost:3001`)
   - Terminal 2 (Versi Aman): `npm run start:aman` (berjalan di `http://localhost:3002`)
3. Buka browser (Chrome / Firefox / Edge) atau gunakan skrip pengujian otomatis:
   ```bash
   npm run test:security
   ```

---

## Skenario 1: SQL Injection Authentication Bypass

### Kondisi Sebelum Patch (Versi Rentan - Port 3001)
1. Buka `http://localhost:3001/login`.
2. Pada kolom **Username**, masukkan payload:
   ```sql
   ' OR '1'='1' --
   ```
3. Pada kolom **Password**, masukkan karakter sembarang (contoh: `bebas123`).
4. Klik tombol **Masuk ke Sistem**.
5. **Ekspektasi Hasil Rentan:** Sistem berhasil login dan mengalihkan halaman ke dashboard akun pengguna pertama (`mhs_budi`) tanpa memverifikasi password yang benar.
6. **Tangkapan Layar:** Simpan screenshot berhasil login ke `bukti/rentan/1-sqli-login-rentan.png`.

### Kondisi Sesudah Patch (Versi Aman - Port 3002)
1. Buka `http://localhost:3002/login`.
2. Masukkan payload yang sama pada kolom **Username**:
   ```sql
   ' OR '1'='1' --
   ```
3. Masukkan password sembarang.
4. Klik tombol **Masuk Aman**.
5. **Ekspektasi Hasil Aman:** Sistem menolak login, menampilkan pesan *"Kredensial tidak valid"*, dan menghitung sisa percobaan login.
6. **Tangkapan Layar:** Simpan screenshot penolakan ke `bukti/aman/1-sqli-login-aman.png`.

---

## Skenario 2: Insecure Direct Object References (IDOR) pada Transkrip Nilai

### Kondisi Sebelum Patch (Versi Rentan - Port 3001)
1. Buka `http://localhost:3001/login`.
2. Login menggunakan akun Mahasiswa 1:
   - Username: `mhs_budi`
   - Password: `BudiPass123!`
3. Klik menu **Nilai** atau akses `http://localhost:3001/grades`.
4. Perhatikan bahwa URL menampilkan nilai milik Budi (student_id = 1).
5. Ubah parameter pada address bar browser menjadi:
   ```text
   http://localhost:3001/grades?student_id=2
   ```
6. Tekan Enter.
7. **Ekspektasi Hasil Rentan:** Data transkrip nilai milik Mahasiswa 2 (**Siti Rahmawati**, NIM: 20240102) ditampilkan secara utuh padahal sesi yang aktif adalah Budi Wicaksono.
8. **Tangkapan Layar:** Simpan screenshot kebocoran data ke `bukti/rentan/2-idor-nilai-rentan.png`.

### Kondisi Sesudah Patch (Versi Aman - Port 3002)
1. Buka `http://localhost:3002/login`.
2. Login sebagai Budi:
   - Username: `mhs_budi`
   - Password: `BudiPass123!`
3. Buka menu **Nilai** (`http://localhost:3002/grades`).
4. Coba manipulasi URL pada address bar menjadi:
   ```text
   http://localhost:3002/grades?student_id=2
   ```
5. Tekan Enter.
6. **Ekspektasi Hasil Aman:** Parameter `student_id=2` diabaikan oleh server. Halaman tetap menampilkan transkrip milik **Budi Wicaksono** sesuai sesi yang terotentikasi.
7. **Tangkapan Layar:** Simpan screenshot pencegahan ke `bukti/aman/2-idor-nilai-aman.png`.

---

## Skenario 3: Stored Cross-Site Scripting (Stored XSS) pada Forum Diskusi

### Kondisi Sebelum Patch (Versi Rentan - Port 3001)
1. Login sebagai `mhs_budi` di `http://localhost:3001`.
2. Buka menu **Forum** (`http://localhost:3001/forum`).
3. Pada formulir **Mulai Diskusi Baru**, isi:
   - Topik Diskusi: `Uji Coba Fitur Forum`
   - Isi Pesan: `<script>alert('VULNERABLE XSS BERHASIL DI RUN: ' + document.domain)</script>`
4. Klik **Publikasikan Pesan**.
5. **Ekspektasi Hasil Rentan:** Browser langsung memunculkan pop-up dialog peringatan (*alert*) JavaScript. Setiap kali halaman forum dibuka kembali atau dibuka oleh akun lain (dosen/admin), dialog alert akan selalu muncul.
6. **Tangkapan Layar:** Simpan screenshot alert pop-up ke `bukti/rentan/3-xss-forum-rentan.png`.

### Kondisi Sesudah Patch (Versi Aman - Port 3002)
1. Login sebagai `mhs_budi` di `http://localhost:3002`.
2. Buka menu **Forum** (`http://localhost:3002/forum`).
3. Masukkan judul dan payload yang sama persis:
   - Topik: `Uji Coba Fitur Forum`
   - Isi Pesan: `<script>alert('VULNERABLE XSS BERHASIL DI RUN: ' + document.domain)</script>`
4. Klik **Publikasikan Pesan**.
5. **Ekspektasi Hasil Aman:** Tidak ada dialog alert yang muncul. Tag skrip ditampilkan sebagai teks biasa yang aman (`&lt;script&gt;...`), dan header CSP aktif mencegah injeksi skrip.
6. **Tangkapan Layar:** Simpan screenshot teks ter-encode ke `bukti/aman/3-xss-forum-aman.png`.

---

## Skenario 4: Brute Force Login & Rate Limiting

### Kondisi Sebelum Patch (Versi Rentan - Port 3001)
1. Buka `http://localhost:3001/login`.
2. Masukkan username `mhs_budi` dengan password acak yang salah secara berulang-ulang (> 10 kali).
3. **Ekspektasi Hasil Rentan:** Tidak ada penghentian, tidak ada jeda waktu, semua percobaan diproses terus-menerus tanpa pembatasan.
4. **Tangkapan Layar:** Simpan screenshot perulangan tanpa batas ke `bukti/rentan/4-bruteforce-rentan.png`.

### Kondisi Sesudah Patch (Versi Aman - Port 3002)
1. Buka `http://localhost:3002/login`.
2. Masukkan username `mhs_budi` dengan password salah sebanyak 5 kali berturut-turut.
3. Perhatikan penghitung sisa percobaan (*Sisa percobaan: 4, 3, 2, 1, 0*).
4. Pada percobaan ke-6, kirim formulir kembali.
5. **Ekspektasi Hasil Aman:** Server merespons dengan kode status HTTP **429 (Too Many Requests)** dan menampilkan halaman peringatan pembekuan akun/IP selama 5 menit (*300 detik*).
6. **Tangkapan Layar:** Simpan screenshot halaman lockout ke `bukti/aman/4-bruteforce-aman.png`.

---

## Petunjuk Pengambilan Bukti Tangkapan Layar (Screenshot)

Untuk keperluan pelaporan praktikum KSI:
1. Pastikan area address bar (menampilkan URL dan nomor port `3001` atau `3002`) terlihat jelas pada tangkapan layar.
2. Buka Inspect Element / Developer Tools (Tab *Network* dan *Console*) jika ingin memperlihatkan kode status HTTP (misal: 429 atau 403) atau header keamanan.
3. Simpan berkas gambar ke direktori `bukti/rentan/` dan `bukti/aman/` sesuai nama berkas yang telah distandardisasi di atas.
