/**
 * ============================================================================
 * PORTAL AKADEMIK FIKTIF "SIAKAD NUSANTARA" - VERSI AMAN (SECURE / HARDENED)
 * ============================================================================
 * PENJELASAN KONTROL KEAMANAN:
 * Aplikasi ini merupakan versi yang telah diperbaiki dengan kontrol keamanan
 * standar industri untuk praktikum Keamanan Sistem Informasi (KSI):
 * 1. Prepared Statements (Parameterized Queries) untuk seluruh interaksi SQL.
 * 2. Strict Role-Based & Object-Level Authorization (Pencegahan IDOR & Broken Access Control).
 * 3. Contextual Output Encoding & Sanitasi untuk pencegahan XSS (disertai CSP).
 * 4. Rate Limiting & Account Lockout untuk mitigasi Brute-Force Authentication.
 * 5. Password Hashing (Bcrypt) & Secure Session Management (HttpOnly, Secure Cookies, Session Regeneration).
 * 6. Perlindungan Cross-Site Request Forgery (CSRF Token) pada seluruh formulir mutasi.
 * ============================================================================
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3002;

// Percayai reverse proxy saat berjalan di cloud (PaaS)
app.set('trust proxy', 1);

// Path database terisolasi untuk versi aman
const dbPath = path.join(__dirname, '..', 'database', 'aman.sqlite');
if (!fs.existsSync(dbPath)) {
  console.log('[INFO] Database aman.sqlite belum ada, menginisialisasi otomatis...');
  require(path.join(__dirname, '..', 'database', 'init-db.js'));
}
const db = new DatabaseSync(dbPath);

// Manajemen Sesi Sisi Server (In-Memory Session Store)
const sessions = new Map(); // sessionId -> { user, csrfToken, expiresAt }

// Konfigurasi Upload Berkas yang Aman
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Hanya izinkan tipe berkas dokumen aman
const ALLOWED_MIME_TYPES = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'];
const ALLOWED_EXTENSIONS = ['.pdf', '.doc', '.docx', '.zip'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // KONTROL KEAMANAN: Menggunakan UUID acak dan ekstensi aman, bukan nama asli berkas
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error('Ekstensi berkas tidak diizinkan. Hanya PDF, DOC, DOCX, ZIP.'), null);
    }
    const safeName = crypto.randomUUID() + ext;
    cb(null, safeName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // Maksimal 5 MB
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new Error('Format berkas tidak valid. Hanya berkas dokumen yang diperbolehkan.'));
    }
    cb(null, true);
  }
});

// Middleware Body Parser & Cookie
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// KONTROL KEAMANAN: Security Headers (Content-Security-Policy, X-Content-Type-Options, dll.)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:;");
  next();
});

app.use('/public', express.static(path.join(__dirname, 'public')));
// Berkas upload disajikan dengan header attachment untuk mencegah eksekusi skrip di browser
app.use('/uploads', (req, res, next) => {
  res.setHeader('Content-Disposition', 'attachment');
  next();
}, express.static(uploadDir));

// Helper: Contextual Output Encoding (Mencegah XSS)
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ============================================================================
// KONTROL KEAMANAN: RATE LIMITING & BRUTE FORCE PROTECTION
// ============================================================================
const loginAttempts = new Map(); // key: ip + username -> { count, lockedUntil }
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME_MS = 5 * 60 * 1000; // 5 menit

function checkRateLimit(req, username) {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const key = `${ip}:${username}`;
  const record = loginAttempts.get(key);

  if (!record) return { allowed: true, remaining: MAX_ATTEMPTS };

  const now = Date.now();
  if (record.lockedUntil && now < record.lockedUntil) {
    const remainingSeconds = Math.ceil((record.lockedUntil - now) / 1000);
    return { allowed: false, remainingSeconds };
  }

  // Jika waktu lockout sudah berlalu, reset
  if (record.lockedUntil && now >= record.lockedUntil) {
    loginAttempts.delete(key);
    return { allowed: true, remaining: MAX_ATTEMPTS };
  }

  return { allowed: true, remaining: MAX_ATTEMPTS - record.count };
}

function recordFailedAttempt(req, username) {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const key = `${ip}:${username}`;
  const now = Date.now();
  let record = loginAttempts.get(key) || { count: 0, lockedUntil: null };

  record.count += 1;
  if (record.count >= MAX_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_TIME_MS;
    console.log(`[AMAN] Akun/IP ${key} TERKUNCI selama 5 menit karena ${record.count} kali gagal login berturut-turut.`);
  }
  loginAttempts.set(key, record);

  // Catat ke audit log di database (Parameterized)
  try {
    db.prepare(`INSERT INTO login_logs (ip_address, username, status) VALUES (?, ?, 'FAILED')`).run(ip, username);
  } catch (e) {
    console.error(e);
  }
}

function recordSuccessfulAttempt(req, username) {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const key = `${ip}:${username}`;
  loginAttempts.delete(key);

  try {
    db.prepare(`INSERT INTO login_logs (ip_address, username, status) VALUES (?, ?, 'SUCCESS')`).run(ip, username);
  } catch (e) {
    console.error(e);
  }
}

// ============================================================================
// KONTROL KEAMANAN: MANAJEMEN SESI & CSRF
// ============================================================================
app.use((req, res, next) => {
  const sessionId = req.cookies.session_id;
  if (sessionId && sessions.has(sessionId)) {
    const sessionData = sessions.get(sessionId);
    if (Date.now() < sessionData.expiresAt) {
      req.user = sessionData.user;
      req.csrfToken = sessionData.csrfToken;
      req.sessionId = sessionId;
      // Perpanjang masa aktif sesi (sliding session)
      sessionData.expiresAt = Date.now() + 30 * 60 * 1000;
    } else {
      sessions.delete(sessionId);
    }
  }
  next();
});

// Middleware Verifikasi CSRF Token
function verifyCsrf(req, res, next) {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (!token || token !== req.csrfToken) {
      return res.status(403).send(`
        <div style="font-family:sans-serif; padding:40px; text-align:center;">
          <h2 style="color:#b91c1c;">403 Forbidden - Validasi CSRF Token Gagal</h2>
          <p>Permintaan ditolak untuk mencegah serangan Cross-Site Request Forgery.</p>
          <a href="/" style="display:inline-block; margin-top:16px; padding:8px 16px; background:#0f766e; color:#fff; text-decoration:none; border-radius:4px;">Kembali</a>
        </div>
      `);
    }
  }
  next();
}

// Middleware Pemeriksaan Login
function requireAuth(req, res, next) {
  if (!req.user) {
    return res.redirect('/login?error=Silakan+login+terlebih+dahulu');
  }
  next();
}

// Middleware Otorisasi Berbasis Peran (RBAC)
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.redirect('/login');
    if (!roles.includes(req.user.role)) {
      return res.status(403).send(`
        <div style="font-family:sans-serif; padding:40px; text-align:center;">
          <h2 style="color:#b91c1c;">403 Forbidden - Akses Ditolak</h2>
          <p>Peran akun Anda (<code>${escapeHtml(req.user.role)}</code>) tidak memiliki izin untuk mengakses sumber daya ini.</p>
          <a href="/" style="display:inline-block; margin-top:16px; padding:8px 16px; background:#0f766e; color:#fff; text-decoration:none; border-radius:4px;">Kembali ke Dashboard</a>
        </div>
      `);
    }
    next();
  };
}

// Template Helper Header
function renderHeader(title, user, currentPath) {
  return `
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(title)} - SIAKAD Aman (Lab KSI)</title>
  <link rel="stylesheet" href="/public/style.css">
</head>
<body>
  <div class="env-banner env-aman">
    🛡️ VERSI AMAN (HARDENED) - IMPLEMENTASI KONTROL KEAMANAN LENGKAP (PORT 3002)
  </div>
  <nav class="navbar">
    <a href="/" class="navbar-brand">
      🎓 SIAKAD NUSANTARA <span style="font-size:12px;color:#16a34a;">[AMAN / HARDENED]</span>
    </a>
    <ul class="navbar-nav">
      ${user ? `
        <li><a href="/" class="${currentPath === '/' ? 'active' : ''}">Dashboard</a></li>
        <li><a href="/grades" class="${currentPath === '/grades' ? 'active' : ''}">Nilai</a></li>
        <li><a href="/assignments" class="${currentPath === '/assignments' ? 'active' : ''}">Tugas</a></li>
        <li><a href="/forum" class="${currentPath === '/forum' ? 'active' : ''}">Forum</a></li>
        ${user.role === 'admin' ? `<li><a href="/admin/users" class="${currentPath === '/admin/users' ? 'active' : ''}">Kelola User</a></li>` : ''}
        <li><span class="user-badge">${escapeHtml(user.role)}: ${escapeHtml(user.username)}</span></li>
        <li><a href="/logout" class="btn btn-danger btn-sm" style="color:white;">Logout</a></li>
      ` : `
        <li><a href="/login" class="active">Login</a></li>
      `}
    </ul>
  </nav>
  <div class="container">
`;
}

function renderFooter() {
  return `
  </div>
  <footer style="text-align: center; padding: 20px; font-size: 13px; color: #64748b;">
    Praktikum Keamanan Sistem Informasi &copy; 2026 - Modul Implementasi Kontrol Keamanan Aplikasi Web
  </footer>
</body>
</html>
`;
}

// ============================================================================
// 1. AUTENTIKASI AMAN: LOGIN DENGAN PREPARED STATEMENT, BCRYPT, & RATE LIMITING
// ============================================================================

app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/');
  const msg = req.query.msg || '';
  const error = req.query.error || '';

  const html = `
    ${renderHeader('Login Portal', null, '/login')}
    <div style="max-width: 440px; margin: 40px auto;">
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Login SIAKAD (Versi Aman)</h2>
        </div>
        ${error ? `<div class="alert alert-danger">${escapeHtml(error)}</div>` : ''}
        ${msg ? `<div class="alert alert-success">${escapeHtml(msg)}</div>` : ''}
        <form method="POST" action="/login">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" placeholder="Contoh: mhs_budi" required autocomplete="username">
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" placeholder="Masukkan password" required autocomplete="current-password">
          </div>
          <button type="submit" class="btn btn-primary" style="width: 100%;">Masuk Aman</button>
        </form>
        <div style="margin-top: 18px; padding-top: 14px; border-top: 1px dashed #cbd5e1; font-size: 12px; color: #64748b;">
          <strong>Kredensial Akun Fiktif untuk Pengujian:</strong><br>
          • Mahasiswa: <code>mhs_budi</code> / <code>BudiPass123!</code><br>
          • Mahasiswa 2: <code>mhs_siti</code> / <code>SitiPass123!</code><br>
          • Dosen: <code>dosen_hendra</code> / <code>DosenPass123!</code><br>
          • Admin: <code>admin_fajar</code> / <code>AdminPass123!</code><br>
          <em style="color:#0f766e;">Keamanan Aktif: Bcrypt Hash, Prepared Statement, Anti Brute-Force (Lockout 5x).</em>
        </div>
      </div>
    </div>
    ${renderFooter()}
  `;
  res.send(html);
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (!username || !password) {
    return res.redirect('/login?error=Username+dan+password+wajib+diisi');
  }

  // 1. Periksa Batas Percobaan (Rate Limiting)
  const rateLimitStatus = checkRateLimit(req, username);
  if (!rateLimitStatus.allowed) {
    return res.status(429).send(`
      ${renderHeader('Batas Percobaan Terlampaui', null, '/login')}
      <div style="max-width: 500px; margin: 40px auto;">
        <div class="card" style="border-left: 4px solid #dc2626;">
          <h2 class="card-title" style="color: #dc2626;">Akun / IP Sementara Dibekukan</h2>
          <p style="margin: 12px 0;">Terlalu banyak percobaan login yang gagal untuk akun ini. Sesuai kebijakan keamanan, silakan tunggu <strong>${rateLimitStatus.remainingSeconds} detik</strong> sebelum mencoba kembali.</p>
          <a href="/login" class="btn btn-primary btn-sm">Segarkan Halaman</a>
        </div>
      </div>
      ${renderFooter()}
    `);
  }

  // 2. Query Pengguna Menggunakan PREPARED STATEMENT (Mencegah SQL Injection)
  let user;
  try {
    const stmt = db.prepare(`SELECT * FROM users WHERE username = ? AND is_active = 1`);
    user = stmt.get(username);
  } catch (err) {
    console.error(`[AMAN] Database query error:`, err);
    return res.redirect('/login?error=Terjadi+kesalahan+pada+sistem');
  }

  // 3. Verifikasi Password Menggunakan Bcrypt
  if (!user || !bcrypt.compareSync(password, user.password)) {
    recordFailedAttempt(req, username);
    const updatedStatus = checkRateLimit(req, username);
    const sisa = updatedStatus.remaining !== undefined ? updatedStatus.remaining : 0;
    return res.redirect(`/login?error=Kredensial+tidak+valid.+Sisa+percobaan:+${sisa}`);
  }

  // 4. Reset Pencatatan Percobaan Login Setelah Sukses
  recordSuccessfulAttempt(req, username);

  // 5. Buat Sesi Baru Secara Kriptografis (Cegah Session Fixation)
  const newSessionId = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(24).toString('hex');

  sessions.set(newSessionId, {
    user,
    csrfToken,
    expiresAt: Date.now() + 30 * 60 * 1000 // 30 Menit
  });

  // Set Cookie dengan Atribut HttpOnly dan SameSite
  res.cookie('session_id', newSessionId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  });

  res.redirect('/');
});

app.get('/logout', (req, res) => {
  if (req.sessionId) {
    sessions.delete(req.sessionId);
  }
  res.clearCookie('session_id');
  res.redirect('/login?msg=Berhasil+logout+secara+aman');
});

// ============================================================================
// 2. DASHBOARD UTAMA
// ============================================================================

app.get('/', requireAuth, (req, res) => {
  const user = req.user;
  let roleDashboardHtml = '';

  if (user.role === 'mahasiswa') {
    roleDashboardHtml = `
      <div class="card">
        <h3 class="card-title">Menu Mahasiswa</h3>
        <p style="margin-bottom: 16px;">Selamat datang, <strong>${escapeHtml(user.full_name)}</strong> (NIM: ${escapeHtml(user.identity_number)}).</p>
        <div style="display: flex; gap: 12px;">
          <a href="/grades" class="btn btn-primary">Lihat Nilai Saya</a>
          <a href="/assignments" class="btn btn-primary">Unggah Tugas Kuliah</a>
          <a href="/forum" class="btn btn-primary">Forum Diskusi</a>
        </div>
      </div>
    `;
  } else if (user.role === 'dosen') {
    roleDashboardHtml = `
      <div class="card">
        <h3 class="card-title">Portal Dosen Pengampu</h3>
        <p style="margin-bottom: 16px;">Selamat datang Bapak/Ibu <strong>${escapeHtml(user.full_name)}</strong> (NIP: ${escapeHtml(user.identity_number)}).</p>
        <div style="display: flex; gap: 12px;">
          <a href="/grades" class="btn btn-primary">Rekapitulasi Nilai Mahasiswa</a>
          <a href="/assignments" class="btn btn-primary">Periksa & Nilai Tugas</a>
          <a href="/forum" class="btn btn-primary">Forum Diskusi Akademik</a>
        </div>
      </div>
    `;
  } else if (user.role === 'admin') {
    roleDashboardHtml = `
      <div class="card">
        <h3 class="card-title">Panel Kontrol Administrator</h3>
        <p style="margin-bottom: 16px;">Selamat datang, <strong>${escapeHtml(user.full_name)}</strong>. Anda memiliki wewenang manajemen akun.</p>
        <div style="display: flex; gap: 12px;">
          <a href="/admin/users" class="btn btn-primary">Kelola Akun Mahasiswa & Dosen</a>
          <a href="/forum" class="btn btn-primary">Pantau Forum Diskusi</a>
        </div>
      </div>
    `;
  }

  const html = `
    ${renderHeader('Dashboard', user, '/')}
    <div class="page-header">
      <h1 class="page-title">Dashboard Akademik</h1>
      <p class="page-subtitle">Portal Informasi Akademik Institut Teknologi & Sains Nusantara (Fiktif) - Versi Aman</p>
    </div>
    ${roleDashboardHtml}
    ${renderFooter()}
  `;
  res.send(html);
});

// ============================================================================
// 3. FITUR NILAI (PERBAIKAN IDOR & PREPARED STATEMENT)
// KONTROL KEAMANAN:
// Mahasiswa HANYA diizinkan melihat nilainya sendiri (student_id terikat ke sesi).
// Parameter query student_id dari luar diabaikan untuk mahasiswa.
// Pencarian disaring menggunakan parameterized query (Mencegah SQLi).
// ============================================================================

app.get('/grades', requireAuth, (req, res) => {
  const user = req.user;
  let targetStudentId = user.id;

  // KONTROL KEAMANAN IDOR:
  // Jika role adalah mahasiswa, PAKSA student_id mengambil dari user.id di sesi.
  // Jika dosen atau admin, mereka diperbolehkan melihat student_id tertentu.
  if (user.role === 'mahasiswa') {
    targetStudentId = user.id; // Tidak pernah percaya input parameter req.query untuk mahasiswa
  } else if (['dosen', 'admin'].includes(user.role)) {
    if (req.query.student_id) {
      const parsed = parseInt(req.query.student_id, 10);
      if (!isNaN(parsed)) {
        targetStudentId = parsed;
      }
    }
  }

  const search = (req.query.search || '').trim();

  // KONTROL KEAMANAN SQL INJECTION: Gunakan Prepared Statement dengan parameter terikat (?)
  let sql = `
    SELECT g.*, c.code AS course_code, c.name AS course_name, c.credits, u.full_name AS student_name, u.identity_number AS nim
    FROM grades g
    JOIN courses c ON g.course_id = c.id
    JOIN users u ON g.student_id = u.id
    WHERE g.student_id = ?
  `;
  const params = [targetStudentId];

  if (search) {
    sql += ` AND c.name LIKE ?`;
    params.push(`%${search}%`);
  }

  let gradeList = [];
  let studentInfo = null;
  try {
    gradeList = db.prepare(sql).all(...params);
    studentInfo = db.prepare(`SELECT full_name, identity_number FROM users WHERE id = ?`).get(targetStudentId);
  } catch (err) {
    console.error(`[AMAN] Error query grades:`, err);
  }

  const rowsHtml = gradeList.map((g, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td><strong>${escapeHtml(g.course_code)}</strong></td>
      <td>${escapeHtml(g.course_name)}</td>
      <td>${escapeHtml(g.credits)} SKS</td>
      <td>${escapeHtml(g.assignment_score)}</td>
      <td>${escapeHtml(g.mid_score)}</td>
      <td>${escapeHtml(g.final_score)}</td>
      <td><span class="badge badge-grade-${escapeHtml(g.letter_grade.charAt(0))}">${escapeHtml(g.letter_grade)}</span></td>
    </tr>
  `).join('');

  // Dropdown pilihan mahasiswa untuk Dosen/Admin
  let studentSelectDropdown = '';
  if (['dosen', 'admin'].includes(user.role)) {
    const allStudents = db.prepare(`SELECT id, full_name, identity_number FROM users WHERE role = 'mahasiswa'`).all();
    studentSelectDropdown = `
      <form method="GET" action="/grades" style="margin-bottom: 16px; display: flex; gap: 8px; align-items: center;">
        <label style="font-weight:600; font-size:14px;">Pilih Mahasiswa:</label>
        <select name="student_id" class="form-control" style="width: 250px;">
          ${allStudents.map(s => `
            <option value="${s.id}" ${s.id === targetStudentId ? 'selected' : ''}>
              ${escapeHtml(s.full_name)} (${escapeHtml(s.identity_number)})
            </option>
          `).join('')}
        </select>
        <button type="submit" class="btn btn-primary btn-sm">Tampilkan</button>
      </form>
    `;
  }

  const html = `
    ${renderHeader('Daftar Nilai', user, '/grades')}
    <div class="page-header">
      <h1 class="page-title">Transkrip Nilai Akademik</h1>
      <p class="page-subtitle">
        Menampilkan nilai untuk mahasiswa: 
        <strong>${studentInfo ? escapeHtml(studentInfo.full_name) : 'Tidak Diketahui'}</strong> 
        (NIM: ${studentInfo ? escapeHtml(studentInfo.identity_number) : '-'})
      </p>
    </div>

    <div class="card">
      ${studentSelectDropdown}

      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <form method="GET" action="/grades" style="display: flex; gap: 8px;">
          ${user.role !== 'mahasiswa' ? `<input type="hidden" name="student_id" value="${targetStudentId}">` : ''}
          <input type="text" name="search" class="form-control" placeholder="Cari mata kuliah..." value="${escapeHtml(search)}">
          <button type="submit" class="btn btn-primary btn-sm">Filter</button>
        </form>
        <div style="font-size: 13px; color: #166534; background: #dcfce7; padding: 4px 10px; border-radius: 4px;">
          🛡️ Keamanan IDOR: Mahasiswa tidak dapat mengubah ID target; query diamankan dengan Prepared Statement.
        </div>
      </div>

      <div class="table-responsive">
        <table class="table">
          <thead>
            <tr>
              <th>No</th>
              <th>Kode</th>
              <th>Mata Kuliah</th>
              <th>SKS</th>
              <th>Tugas</th>
              <th>UTS</th>
              <th>UAS</th>
              <th>Nilai Huruf</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml.length > 0 ? rowsHtml : '<tr><td colspan="8" style="text-align:center;">Tidak ada data nilai ditemukan.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    ${renderFooter()}
  `;
  res.send(html);
});

// ============================================================================
// 4. FITUR TUGAS (UPLOAD & PENILAIAN DENGAN RBAC DAN CSRF TOKEN)
// ============================================================================

app.get('/assignments', requireAuth, (req, res) => {
  const user = req.user;
  const msg = req.query.msg || '';
  const error = req.query.error || '';

  const courses = db.prepare(`SELECT * FROM courses`).all();

  let assignmentsQuery = `
    SELECT a.*, c.name AS course_name, u.full_name AS student_name, u.identity_number AS nim
    FROM assignments a
    JOIN courses c ON a.course_id = c.id
    JOIN users u ON a.student_id = u.id
  `;
  const params = [];
  if (user.role === 'mahasiswa') {
    assignmentsQuery += ` WHERE a.student_id = ?`;
    params.push(user.id);
  }
  assignmentsQuery += ` ORDER BY a.submitted_at DESC`;

  const assignments = db.prepare(assignmentsQuery).all(...params);

  const assignmentsRows = assignments.map((a, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${escapeHtml(a.student_name)} (${escapeHtml(a.nim)})</td>
      <td>${escapeHtml(a.course_name)}</td>
      <td><strong>${escapeHtml(a.title)}</strong></td>
      <td><a href="/uploads/${escapeHtml(a.file_path)}" class="btn btn-sm" style="background:#e2e8f0;">Unduh Berkas</a></td>
      <td>${escapeHtml(a.submitted_at)}</td>
      <td>${a.score !== null ? `<span class="badge badge-grade-A">${escapeHtml(a.score)}</span>` : '<span style="color:#94a3b8;">Belum dinilai</span>'}</td>
      <td>${escapeHtml(a.feedback || '-')}</td>
      ${user.role === 'dosen' ? `
        <td>
          <form method="POST" action="/assignments/grade" style="display:flex; gap:4px;">
            <input type="hidden" name="_csrf" value="${req.csrfToken}">
            <input type="hidden" name="assignment_id" value="${a.id}">
            <input type="number" step="0.1" max="100" min="0" name="score" class="form-control" placeholder="Nilai" style="width:70px; padding:4px;" required value="${a.score !== null ? a.score : ''}">
            <input type="text" name="feedback" class="form-control" placeholder="Catatan" style="width:120px; padding:4px;" value="${escapeHtml(a.feedback || '')}">
            <button type="submit" class="btn btn-primary btn-sm">Simpan</button>
          </form>
        </td>
      ` : ''}
    </tr>
  `).join('');

  const html = `
    ${renderHeader('Kelola Tugas', user, '/assignments')}
    <div class="page-header">
      <h1 class="page-title">Manajemen Tugas Perkuliahan</h1>
      <p class="page-subtitle">Unggah berkas laporan praktikum dan lihat umpan balik dosen (Terproteksi CSRF & RBAC)</p>
    </div>

    ${msg ? `<div class="alert alert-success">${escapeHtml(msg)}</div>` : ''}
    ${error ? `<div class="alert alert-danger">${escapeHtml(error)}</div>` : ''}

    ${user.role === 'mahasiswa' ? `
      <div class="card">
        <h3 class="card-title">Unggah Tugas Baru</h3>
        <form method="POST" action="/assignments/upload" enctype="multipart/form-data">
          <input type="hidden" name="_csrf" value="${req.csrfToken}">
          <div class="grid-2">
            <div class="form-group">
              <label class="form-label">Mata Kuliah</label>
              <select name="course_id" class="form-control" required>
                ${courses.map(c => `<option value="${c.id}">${escapeHtml(c.code)} - ${escapeHtml(c.name)}</option>`).join('')}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Judul Tugas / Laporan</label>
              <input type="text" name="title" class="form-control" placeholder="Contoh: Laporan Modul 5" required maxlength="150">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Pilih Berkas Tugas (Hanya PDF, DOC, DOCX, ZIP; Maksimal 5MB)</label>
            <input type="file" name="file" class="form-control" accept=".pdf,.doc,.docx,.zip" required>
          </div>
          <button type="submit" class="btn btn-primary">Unggah Berkas Secara Aman</button>
        </form>
      </div>
    ` : ''}

    <div class="card">
      <h3 class="card-title">${user.role === 'dosen' ? 'Daftar Pengumpulan Tugas Mahasiswa' : 'Riwayat Pengumpulan Tugas Anda'}</h3>
      <div class="table-responsive">
        <table class="table">
          <thead>
            <tr>
              <th>No</th>
              <th>Mahasiswa</th>
              <th>Mata Kuliah</th>
              <th>Judul Tugas</th>
              <th>Berkas</th>
              <th>Waktu Unggah</th>
              <th>Nilai</th>
              <th>Umpan Balik</th>
              ${user.role === 'dosen' ? '<th>Aksi Penilaian</th>' : ''}
            </tr>
          </thead>
          <tbody>
            ${assignmentsRows.length > 0 ? assignmentsRows : '<tr><td colspan="9" style="text-align:center;">Belum ada tugas yang dikumpulkan.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    ${renderFooter()}
  `;
  res.send(html);
});

// Upload hanya boleh diakses peran Mahasiswa
app.post('/assignments/upload', requireAuth, requireRole('mahasiswa'), verifyCsrf, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.redirect(`/assignments?error=${encodeURIComponent(err.message)}`);
    }

    const user = req.user;
    const courseId = parseInt(req.body.course_id, 10);
    const title = String(req.body.title || '').trim();
    const file = req.file;

    if (!file || isNaN(courseId) || !title) {
      return res.redirect('/assignments?error=Data+pengunggahan+tugas+tidak+lengkap');
    }

    // Prepared Statement
    db.prepare(`
      INSERT INTO assignments (student_id, course_id, title, file_path, original_filename)
      VALUES (?, ?, ?, ?, ?)
    `).run(user.id, courseId, title, file.filename, file.originalname);

    res.redirect('/assignments?msg=Tugas+berhasil+diunggah+secara+aman');
  });
});

// Penilaian hanya boleh diakses peran Dosen
app.post('/assignments/grade', requireAuth, requireRole('dosen'), verifyCsrf, (req, res) => {
  const assignmentId = parseInt(req.body.assignment_id, 10);
  const score = parseFloat(req.body.score);
  const feedback = String(req.body.feedback || '').trim();

  if (isNaN(assignmentId) || isNaN(score) || score < 0 || score > 100) {
    return res.redirect('/assignments?error=Format+nilai+tidak+valid+(0-100)');
  }

  // Prepared Statement
  db.prepare(`
    UPDATE assignments
    SET score = ?, feedback = ?
    WHERE id = ?
  `).run(score, feedback, assignmentId);

  res.redirect('/assignments?msg=Penilaian+berhasil+disimpan');
});

// ============================================================================
// 5. FITUR FORUM DISKUSI (PERBAIKAN STORED XSS DENGAN OUTPUT ENCODING & CSRF)
// ============================================================================

app.get('/forum', requireAuth, (req, res) => {
  const user = req.user;
  const msg = req.query.msg || '';

  const posts = db.prepare(`
    SELECT f.*, u.full_name AS author_name, u.role AS author_role
    FROM forum_posts f
    JOIN users u ON f.user_id = u.id
    ORDER BY f.created_at DESC
  `).all();

  // KONTROL KEAMANAN XSS: Seluruh konten di-encode secara ketat menggunakan escapeHtml()
  // Tag seperti <script>alert(1)</script> akan diubah menjadi &lt;script&gt;alert(1)&lt;/script&gt;
  const postsHtml = posts.map(p => `
    <div class="post-card">
      <div class="post-title">${escapeHtml(p.title)}</div>
      <div class="post-meta">
        Oleh <strong>${escapeHtml(p.author_name)}</strong> (${escapeHtml(p.author_role)}) &bull; ${escapeHtml(p.created_at)}
      </div>
      <div class="post-content">
        ${escapeHtml(p.content).replace(/\n/g, '<br>')}
      </div>
    </div>
  `).join('');

  const html = `
    ${renderHeader('Forum Diskusi', user, '/forum')}
    <div class="page-header">
      <h1 class="page-title">Forum Diskusi Akademik</h1>
      <p class="page-subtitle">Ruang diskusi aman (Terproteksi Stored XSS & CSRF)</p>
    </div>

    ${msg ? `<div class="alert alert-success">${escapeHtml(msg)}</div>` : ''}

    <div class="card">
      <h3 class="card-title">Mulai Diskusi Baru</h3>
      <form method="POST" action="/forum">
        <input type="hidden" name="_csrf" value="${req.csrfToken}">
        <div class="form-group">
          <label class="form-label">Topik Diskusi</label>
          <input type="text" name="title" class="form-control" placeholder="Judul topik..." required maxlength="150">
        </div>
        <div class="form-group">
          <label class="form-label">Isi Pesan / Pertanyaan</label>
          <textarea name="content" class="form-control" placeholder="Tuliskan isi pesan diskusi..." required maxlength="1000"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Publikasikan Pesan</button>
      </form>
      <div style="margin-top: 10px; font-size: 12px; color: #166534;">
        🛡️ Proteksi XSS Aktif: Seluruh karakter HTML dienkode (escaped) sebelum dirender ke DOM browser.
      </div>
    </div>

    <div class="card">
      <h3 class="card-title">Daftar Diskusi Terbaru</h3>
      ${postsHtml.length > 0 ? postsHtml : '<p style="color:#64748b;">Belum ada topik diskusi.</p>'}
    </div>
    ${renderFooter()}
  `;
  res.send(html);
});

app.post('/forum', requireAuth, verifyCsrf, (req, res) => {
  const user = req.user;
  const title = String(req.body.title || '').trim().slice(0, 150);
  const content = String(req.body.content || '').trim().slice(0, 1000);

  if (!title || !content) {
    return res.redirect('/forum?msg=Judul+dan+isi+pesan+tidak+boleh+kosong');
  }

  // Prepared Statement
  db.prepare(`
    INSERT INTO forum_posts (user_id, title, content)
    VALUES (?, ?, ?)
  `).run(user.id, title, content);

  res.redirect('/forum?msg=Pesan+berhasil+dipublikasikan');
});

// ============================================================================
// 6. FITUR MANAJEMEN AKUN ADMIN (KONTROL RBAC KETAT, BCRYPT, PREPARED STATEMENT)
// ============================================================================

app.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  const user = req.user;
  const msg = req.query.msg || '';
  const error = req.query.error || '';

  const userList = db.prepare(`SELECT * FROM users ORDER BY role, id`).all();

  const userRows = userList.map((u, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td><strong>${escapeHtml(u.username)}</strong></td>
      <td>${escapeHtml(u.full_name)}</td>
      <td><span class="user-badge">${escapeHtml(u.role)}</span></td>
      <td>${escapeHtml(u.identity_number)}</td>
      <td>${escapeHtml(u.email)}</td>
      <td>${u.is_active ? '<span style="color:#16a34a;">Aktif</span>' : '<span style="color:#dc2626;">Non-aktif</span>'}</td>
      <td>
        <form method="POST" action="/admin/users/toggle" style="display:inline;">
          <input type="hidden" name="_csrf" value="${req.csrfToken}">
          <input type="hidden" name="user_id" value="${u.id}">
          <input type="hidden" name="current_status" value="${u.is_active}">
          <button type="submit" class="btn btn-sm ${u.is_active ? 'btn-danger' : 'btn-primary'}">
            ${u.is_active ? 'Nonaktifkan' : 'Aktifkan'}
          </button>
        </form>
      </td>
    </tr>
  `).join('');

  const html = `
    ${renderHeader('Kelola Pengguna', user, '/admin/users')}
    <div class="page-header">
      <h1 class="page-title">Manajemen Akun Pengguna</h1>
      <p class="page-subtitle">Pengelolaan akun terotentikasi dan terotorisasi penuh (Admin Only)</p>
    </div>

    ${msg ? `<div class="alert alert-success">${escapeHtml(msg)}</div>` : ''}
    ${error ? `<div class="alert alert-danger">${escapeHtml(error)}</div>` : ''}

    <div class="card">
      <h3 class="card-title">Tambah Akun Baru</h3>
      <form method="POST" action="/admin/users/create">
        <input type="hidden" name="_csrf" value="${req.csrfToken}">
        <div class="grid-2">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" required pattern="[a-zA-Z0-9_]{4,30}">
          </div>
          <div class="form-group">
            <label class="form-label">Password (Minimal 8 Karakter)</label>
            <input type="password" name="password" class="form-control" required minlength="8">
          </div>
          <div class="form-group">
            <label class="form-label">Nama Lengkap</label>
            <input type="text" name="full_name" class="form-control" required>
          </div>
          <div class="form-group">
            <label class="form-label">Peran (Role)</label>
            <select name="role" class="form-control" required>
              <option value="mahasiswa">Mahasiswa</option>
              <option value="dosen">Dosen</option>
              <option value="admin">Administrator</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Nomor Identitas (NIM/NIP)</label>
            <input type="text" name="identity_number" class="form-control" required>
          </div>
          <div class="form-group">
            <label class="form-label">Email</label>
            <input type="email" name="email" class="form-control" required>
          </div>
        </div>
        <button type="submit" class="btn btn-primary">Simpan Akun dengan Hash Bcrypt</button>
      </form>
    </div>

    <div class="card">
      <h3 class="card-title">Daftar Seluruh Pengguna Sistem</h3>
      <div class="table-responsive">
        <table class="table">
          <thead>
            <tr>
              <th>No</th>
              <th>Username</th>
              <th>Nama Lengkap</th>
              <th>Role</th>
              <th>ID Identitas</th>
              <th>Email</th>
              <th>Status</th>
              <th>Aksi</th>
            </tr>
          </thead>
          <tbody>
            ${userRows}
          </tbody>
        </table>
      </div>
    </div>
    ${renderFooter()}
  `;
  res.send(html);
});

app.post('/admin/users/create', requireAuth, requireRole('admin'), verifyCsrf, (req, res) => {
  const { username, password, full_name, role, identity_number, email } = req.body;

  if (!username || !password || password.length < 8) {
    return res.redirect('/admin/users?error=Password+minimal+8+karakter');
  }

  // KONTROL KEAMANAN: Password di-hash menggunakan Bcrypt
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    db.prepare(`
      INSERT INTO users (username, password, full_name, role, identity_number, email)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(username, hashedPassword, full_name, role, identity_number, email);
    res.redirect('/admin/users?msg=Pengguna+baru+berhasil+dibuat+dengan+password+terenkripsi');
  } catch (err) {
    console.error(err);
    res.redirect('/admin/users?error=Gagal+membuat+pengguna+(username+mungkin+sudah+ada)');
  }
});

app.post('/admin/users/toggle', requireAuth, requireRole('admin'), verifyCsrf, (req, res) => {
  const userId = parseInt(req.body.user_id, 10);
  const currentStatus = parseInt(req.body.current_status, 10);
  const newStatus = currentStatus === 1 ? 0 : 1;

  db.prepare(`UPDATE users SET is_active = ? WHERE id = ?`).run(newStatus, userId);
  res.redirect('/admin/users?msg=Status+pengguna+berhasil+diubah');
});

// Jalankan Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER AMAN] Berjalan di http://localhost:${PORT}`);
});
