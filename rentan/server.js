/**
 * ============================================================================
 * PORTAL AKADEMIK FIKTIF "SIAKAD NUSANTARA" - VERSI RENTAN (VULNERABLE)
 * ============================================================================
 * PERINGATAN KEAMANAN:
 * Aplikasi ini SENGAJA memiliki kerentanan keamanan untuk keperluan praktikum
 * mata kuliah Keamanan Sistem Informasi (KSI).
 * HANYA untuk dijalankan di lingkungan lokal/laboratorium tertutup!
 * ============================================================================
 * KERENTANAN YANG DIIMPLEMENTASIKAN:
 * 1. SQL Injection (SQLi) pada fitur login dan pencarian nilai.
 * 2. Insecure Direct Object References (IDOR) pada fitur melihat nilai mahasiswa.
 * 3. Stored Cross-Site Scripting (Stored XSS) pada forum diskusi.
 * 4. Percobaan Login Tanpa Pembatasan (No Rate Limiting / Brute Force Allowed).
 * 5. Broken Access Control & Session Management yang lemah (Plain cookie).
 * ============================================================================
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3001;
const IS_NETLIFY = !!process.env.NETLIFY;
const DB_DIR = process.env.DB_DIR || (IS_NETLIFY ? '/tmp/ksi-m5-db' : path.join(__dirname, '..', 'database'));
const UPLOAD_DIR = process.env.UPLOAD_DIR || (IS_NETLIFY ? '/tmp/ksi-m5-rentan-uploads' : path.join(__dirname, 'uploads'));

// Gatekeeper Lab Terkontrol: Proteksi HTTP Basic Auth untuk Versi Rentan di Lingkungan Online
const LAB_PROTECTION = process.env.LAB_PROTECTED === 'true' || process.env.NODE_ENV === 'production';
const LAB_USER = process.env.LAB_USER || 'praktikan_ksi';
const LAB_PASS = process.env.LAB_PASS || 'lab-terbatas-2026';

if (LAB_PROTECTION) {
  app.use((req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Laboratorium Terisolasi KSI - Akses Terbatas"');
      return res.status(401).send('401 Unauthorized: Akses laboratorium rentan dibatasi untuk penguji berwenang.');
    }
    const [scheme, credentials] = authHeader.split(' ');
    if (scheme !== 'Basic' || !credentials) {
      return res.status(401).send('Format autentikasi tidak valid.');
    }
    const decoded = Buffer.from(credentials, 'base64').toString('utf-8');
    const [user, pass] = decoded.split(':');
    if (user === LAB_USER && pass === LAB_PASS) {
      return next();
    }
    res.setHeader('WWW-Authenticate', 'Basic realm="Laboratorium Terisolasi KSI - Akses Terbatas"');
    return res.status(401).send('401 Unauthorized: Kredensial gerbang lab salah.');
  });
}

// Path database terisolasi untuk versi rentan
const dbPath = path.join(DB_DIR, 'rentan.sqlite');
if (!fs.existsSync(dbPath)) {
  console.log('[INFO] Database rentan.sqlite belum ada, menginisialisasi otomatis...');
  process.env.DB_DIR = DB_DIR;
  require(path.join(__dirname, '..', 'database', 'init-db.js'));
}
const db = new DatabaseSync(dbPath);

// Konfigurasi upload file tugas
const uploadDir = UPLOAD_DIR;
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // RENTAN: Menggunakan nama asli tanpa sanitasi ekstensi
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Middleware umum
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

/**
 * Middleware Autentikasi Sederhana (RENTAN: Menggunakan Cookie Tanpa Tanda Tangan)
 */
app.use((req, res, next) => {
  const userId = req.cookies.user_id;
  if (userId) {
    try {
      // Mengambil user dari DB
      const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(userId);
      if (user) {
        req.user = user;
      }
    } catch (e) {
      console.error(e);
    }
  }
  next();
});

// Helper Header HTML Template
function renderHeader(title, user, currentPath) {
  return `
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <title>${title} - SIAKAD Rentan (Lab KSI)</title>
  <link rel="stylesheet" href="/public/style.css">
</head>
<body>
  <div class="env-banner env-rentan">
    ⚠️ PERINGATAN: INI ADALAH VERSI RENTAN (VULNERABLE) - HANYA UNTUK PRAKTIKUM KEAMANAN SISTEM INFORMASI (PORT 3001)
  </div>
  <nav class="navbar">
    <a href="/" class="navbar-brand">
      🎓 SIAKAD NUSANTARA <span style="font-size:12px;color:#dc2626;">[RENTAN]</span>
    </a>
    <ul class="navbar-nav">
      ${user ? `
        <li><a href="/" class="${currentPath === '/' ? 'active' : ''}">Dashboard</a></li>
        <li><a href="/grades" class="${currentPath === '/grades' ? 'active' : ''}">Nilai</a></li>
        <li><a href="/assignments" class="${currentPath === '/assignments' ? 'active' : ''}">Tugas</a></li>
        <li><a href="/forum" class="${currentPath === '/forum' ? 'active' : ''}">Forum</a></li>
        ${user.role === 'admin' || true ? `<li><a href="/admin/users" class="${currentPath === '/admin/users' ? 'active' : ''}">Kelola User</a></li>` : ''}
        <li><span class="user-badge">${user.role}: ${user.username}</span></li>
        <li><a href="/logout" class="btn btn-danger btn-sm" style="color:white;">Logout</a></li>
      ` : `
        <li><a href="/login" class="active">Login</a></li>
      `}
    </ul>
  </nav>
  <div class="container">
`;
}

// Helper Footer HTML Template
function renderFooter() {
  return `
  </div>
  <footer style="text-align: center; padding: 20px; font-size: 13px; color: #64748b;">
    Praktikum Keamanan Sistem Informasi &copy; 2026 - Modul Pengujian Kerentanan Aplikasi Web
  </footer>
</body>
</html>
`;
}

// ============================================================================
// 1. AUTENTIKASI: LOGIN & LOGOUT
// KERENTANAN 1: SQL INJECTION PADA LOGIN
// KERENTANAN 4: TIDAK ADA BATASAN PERCOBAAN LOGIN (BRUTE FORCE)
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
          <h2 class="card-title">Login SIAKAD (Versi Rentan)</h2>
        </div>
        ${error ? `<div class="alert alert-danger">${error}</div>` : ''}
        ${msg ? `<div class="alert alert-success">${msg}</div>` : ''}
        <form method="POST" action="/login">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" placeholder="Contoh: mhs_budi" required>
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" placeholder="Masukkan password" required>
          </div>
          <button type="submit" class="btn btn-primary" style="width: 100%;">Masuk ke Sistem</button>
        </form>
        <div style="margin-top: 18px; padding-top: 14px; border-top: 1px dashed #cbd5e1; font-size: 12px; color: #64748b;">
          <strong>Kredensial Akun Fiktif untuk Pengujian:</strong><br>
          • Mahasiswa: <code>mhs_budi</code> / <code>BudiPass123!</code><br>
          • Mahasiswa 2: <code>mhs_siti</code> / <code>SitiPass123!</code><br>
          • Dosen: <code>dosen_hendra</code> / <code>DosenPass123!</code><br>
          • Admin: <code>admin_fajar</code> / <code>AdminPass123!</code><br>
          <em style="color:#b91c1c;">Vulnerability Hint: Form ini rentan SQL Injection & Brute Force!</em>
        </div>
      </div>
    </div>
    ${renderFooter()}
  `;
  res.send(html);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // KERENTANAN 1: SQL Injection melalui string concatenation langsung
  // Attacker dapat memasukkan payload: ' OR '1'='1' --
  const rawQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}' AND is_active = 1`;
  console.log(`[RENTAN] Menjalankan Raw Query Login: ${rawQuery}`);

  try {
    const user = db.prepare(rawQuery).get();

    if (user) {
      // KERENTANAN: Cookie sesi polos tanpa httpOnly, tanpa HMAC signing
      res.cookie('user_id', user.id, { httpOnly: false });
      return res.redirect('/');
    } else {
      return res.redirect('/login?error=Username+atau+password+salah');
    }
  } catch (err) {
    console.error(`[RENTAN] SQL Error: ${err.message}`);
    // Error bocor ke response untuk analisis SQLi
    return res.redirect(`/login?error=Database+Error:+${encodeURIComponent(err.message)}`);
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('user_id');
  res.redirect('/login?msg=Berhasil+logout');
});

// Middleware Cek Login
function requireAuth(req, res, next) {
  if (!req.user) {
    return res.redirect('/login?error=Silakan+login+terlebih+dahulu');
  }
  next();
}

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
        <p style="margin-bottom: 16px;">Selamat datang, <strong>${user.full_name}</strong> (NIM: ${user.identity_number}).</p>
        <div style="display: flex; gap: 12px;">
          <a href="/grades?student_id=${user.id}" class="btn btn-primary">Lihat Nilai Saya</a>
          <a href="/assignments" class="btn btn-primary">Unggah Tugas Kuliah</a>
          <a href="/forum" class="btn btn-primary">Forum Diskusi</a>
        </div>
      </div>
    `;
  } else if (user.role === 'dosen') {
    roleDashboardHtml = `
      <div class="card">
        <h3 class="card-title">Portal Dosen Pengampu</h3>
        <p style="margin-bottom: 16px;">Selamat datang Bapak/Ibu <strong>${user.full_name}</strong> (NIP: ${user.identity_number}).</p>
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
        <p style="margin-bottom: 16px;">Selamat datang, <strong>${user.full_name}</strong>. Anda memiliki wewenang manajemen akun.</p>
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
      <p class="page-subtitle">Portal Informasi Akademik Institut Teknologi & Sains Nusantara (Fiktif)</p>
    </div>
    ${roleDashboardHtml}
    ${renderFooter()}
  `;
  res.send(html);
});

// ============================================================================
// 3. FITUR NILAI
// KERENTANAN 2: INSECURE DIRECT OBJECT REFERENCES (IDOR)
// Parameter student_id diambil dari query string tanpa validasi kepemilikan data!
// Mahasiswa A (ID 1) dapat mengakses nilai Mahasiswa B dengan mengubah ?student_id=2
// ============================================================================

app.get('/grades', requireAuth, (req, res) => {
  const user = req.user;
  
  // KERENTANAN IDOR: Menerima student_id langsung dari request parameter!
  // Jika mahasiswa yang login adalah ID 1, dia dapat mengganti query ?student_id=2
  // Server TIDAK memeriksa apakah user berhak mengakses student_id tersebut.
  const studentId = req.query.student_id || user.id;
  const search = req.query.search || '';

  // KERENTANAN SQL INJECTION KEDUA: Pencarian digabungkan secara langsung
  let sql = `
    SELECT g.*, c.code AS course_code, c.name AS course_name, c.credits, u.full_name AS student_name, u.identity_number AS nim
    FROM grades g
    JOIN courses c ON g.course_id = c.id
    JOIN users u ON g.student_id = u.id
    WHERE g.student_id = ${studentId}
  `;

  if (search) {
    sql += ` AND c.name LIKE '%${search}%'`;
  }

  console.log(`[RENTAN] Query Nilai (IDOR & SQLi): ${sql}`);

  let studentInfo = null;
  let gradeList = [];
  try {
    gradeList = db.prepare(sql).all();
    studentInfo = db.prepare(`SELECT full_name, identity_number FROM users WHERE id = ${studentId}`).get();
  } catch (err) {
    console.error(err);
  }

  const rowsHtml = gradeList.map((g, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td><strong>${g.course_code}</strong></td>
      <td>${g.course_name}</td>
      <td>${g.credits} SKS</td>
      <td>${g.assignment_score}</td>
      <td>${g.mid_score}</td>
      <td>${g.final_score}</td>
      <td><span class="badge badge-grade-${g.letter_grade.charAt(0)}">${g.letter_grade}</span></td>
    </tr>
  `).join('');

  const html = `
    ${renderHeader('Daftar Nilai', user, '/grades')}
    <div class="page-header">
      <h1 class="page-title">Transkrip Nilai Akademik</h1>
      <p class="page-subtitle">
        Menampilkan nilai untuk mahasiswa: 
        <strong>${studentInfo ? studentInfo.full_name : 'Tidak Diketahui'}</strong> 
        (NIM: ${studentInfo ? studentInfo.identity_number : '-'}) 
        <span style="color:#dc2626; font-size:12px;">[student_id = ${studentId}]</span>
      </p>
    </div>

    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <form method="GET" action="/grades" style="display: flex; gap: 8px;">
          <input type="hidden" name="student_id" value="${studentId}">
          <input type="text" name="search" class="form-control" placeholder="Cari mata kuliah..." value="${search}">
          <button type="submit" class="btn btn-primary btn-sm">Filter</button>
        </form>
        <div style="font-size: 13px; color: #dc2626; background: #fee2e2; padding: 4px 10px; border-radius: 4px;">
          🔍 Celah IDOR: Ganti <code>?student_id=2</code> di URL browser untuk membocorkan nilai mahasiswa lain!
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
// 4. FITUR TUGAS (UPLOAD OLEH MAHASISWA & PENILAIAN OLEH DOSEN)
// ============================================================================

app.get('/assignments', requireAuth, (req, res) => {
  const user = req.user;
  const msg = req.query.msg || '';

  const courses = db.prepare(`SELECT * FROM courses`).all();
  
  // Dosen melihat semua tugas, Mahasiswa melihat tugasnya sendiri
  let assignmentsQuery = `
    SELECT a.*, c.name AS course_name, u.full_name AS student_name, u.identity_number AS nim
    FROM assignments a
    JOIN courses c ON a.course_id = c.id
    JOIN users u ON a.student_id = u.id
  `;
  if (user.role === 'mahasiswa') {
    assignmentsQuery += ` WHERE a.student_id = ${user.id}`;
  }
  assignmentsQuery += ` ORDER BY a.submitted_at DESC`;

  const assignments = db.prepare(assignmentsQuery).all();

  const assignmentsRows = assignments.map((a, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${a.student_name} (${a.nim})</td>
      <td>${a.course_name}</td>
      <td><strong>${a.title}</strong></td>
      <td><a href="/uploads/${a.file_path}" target="_blank" class="btn btn-sm" style="background:#e2e8f0;">Unduh File</a></td>
      <td>${a.submitted_at}</td>
      <td>${a.score !== null ? `<span class="badge badge-grade-A">${a.score}</span>` : '<span style="color:#94a3b8;">Belum dinilai</span>'}</td>
      <td>${a.feedback || '-'}</td>
      ${user.role === 'dosen' ? `
        <td>
          <form method="POST" action="/assignments/grade" style="display:flex; gap:4px;">
            <input type="hidden" name="assignment_id" value="${a.id}">
            <input type="number" name="score" class="form-control" placeholder="Nilai" style="width:70px; padding:4px;" required value="${a.score || ''}">
            <input type="text" name="feedback" class="form-control" placeholder="Catatan" style="width:120px; padding:4px;" value="${a.feedback || ''}">
            <button type="submit" class="btn btn-primary btn-sm">Beri Nilai</button>
          </form>
        </td>
      ` : ''}
    </tr>
  `).join('');

  const html = `
    ${renderHeader('Kelola Tugas', user, '/assignments')}
    <div class="page-header">
      <h1 class="page-title">Manajemen Tugas Perkuliahan</h1>
      <p class="page-subtitle">Unggah berkas laporan praktikum dan lihat umpan balik dosen</p>
    </div>

    ${msg ? `<div class="alert alert-success">${msg}</div>` : ''}

    ${user.role === 'mahasiswa' ? `
      <div class="card">
        <h3 class="card-title">Unggah Tugas Baru</h3>
        <form method="POST" action="/assignments/upload" enctype="multipart/form-data">
          <div class="grid-2">
            <div class="form-group">
              <label class="form-label">Mata Kuliah</label>
              <select name="course_id" class="form-control" required>
                ${courses.map(c => `<option value="${c.id}">${c.code} - ${c.name}</option>`).join('')}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Judul Tugas / Laporan</label>
              <input type="text" name="title" class="form-control" placeholder="Contoh: Laporan Modul 5" required>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Pilih Berkas Tugas</label>
            <input type="file" name="file" class="form-control" required>
          </div>
          <button type="submit" class="btn btn-primary">Unggah Tugas</button>
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

app.post('/assignments/upload', requireAuth, upload.single('file'), (req, res) => {
  const user = req.user;
  const { course_id, title } = req.body;
  const file = req.file;

  if (!file) {
    return res.redirect('/assignments?error=Berkas+tidak+ditemukan');
  }

  // RENTAN: Tanpa pengecekan MIME type, ekstensi file, atau batas ukuran file
  db.prepare(`
    INSERT INTO assignments (student_id, course_id, title, file_path, original_filename)
    VALUES (?, ?, ?, ?, ?)
  `).run(user.id, course_id, title, file.filename, file.originalname);

  res.redirect('/assignments?msg=Tugas+berhasil+diunggah');
});

app.post('/assignments/grade', requireAuth, (req, res) => {
  const { assignment_id, score, feedback } = req.body;

  // RENTAN: Tidak ada validasi role sisi server (siapa saja yang kirim POST bisa menilai)
  db.prepare(`
    UPDATE assignments
    SET score = ?, feedback = ?
    WHERE id = ?
  `).run(score, feedback, assignment_id);

  res.redirect('/assignments?msg=Nilai+dan+umpan+balik+berhasil+disimpan');
});

// ============================================================================
// 5. FITUR FORUM DISKUSI
// KERENTANAN 3: STORED CROSS-SITE SCRIPTING (STORED XSS)
// Konten disimpan dan dirender MENTAH ke dalam HTML tanpa sanitasi / HTML encoding!
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

  // KERENTANAN STORED XSS: Konten p.title dan p.content langsung disisipkan tanpa escapeHtml!
  // Jika isi content berupa <script>alert(document.cookie)</script> maka script langsung berjalan.
  const postsHtml = posts.map(p => `
    <div class="post-card">
      <div class="post-title">${p.title}</div>
      <div class="post-meta">
        Oleh <strong>${p.author_name}</strong> (${p.author_role}) &bull; ${p.created_at}
      </div>
      <div class="post-content">
        ${p.content}
      </div>
    </div>
  `).join('');

  const html = `
    ${renderHeader('Forum Diskusi', user, '/forum')}
    <div class="page-header">
      <h1 class="page-title">Forum Diskusi Akademik</h1>
      <p class="page-subtitle">Ruang diskusi materi perkuliahan antara mahasiswa dan dosen</p>
    </div>

    ${msg ? `<div class="alert alert-success">${msg}</div>` : ''}

    <div class="card">
      <h3 class="card-title">Mulai Diskusi Baru</h3>
      <form method="POST" action="/forum">
        <div class="form-group">
          <label class="form-label">Topik Diskusi</label>
          <input type="text" name="title" class="form-control" placeholder="Judul topik..." required>
        </div>
        <div class="form-group">
          <label class="form-label">Isi Pesan / Pertanyaan</label>
          <textarea name="content" class="form-control" placeholder="Tuliskan isi pesan diskusi..." required></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Publikasikan Pesan</button>
      </form>
      <div style="margin-top: 10px; font-size: 12px; color: #dc2626;">
        💡 Petunjuk Lab XSS: Masukkan payload seperti <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code> atau <code>&lt;img src=x onerror="alert(document.cookie)"&gt;</code> untuk memicu kerentanan Stored XSS.
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

app.post('/forum', requireAuth, (req, res) => {
  const user = req.user;
  const { title, content } = req.body;

  // RENTAN: Disimpan tanpa filter atau sanitasi
  db.prepare(`
    INSERT INTO forum_posts (user_id, title, content)
    VALUES (?, ?, ?)
  `).run(user.id, title, content);

  res.redirect('/forum?msg=Pesan+berhasil+dipublikasikan');
});

// ============================================================================
// 6. FITUR MANAJEMEN AKUN ADMIN
// (Rentan Broken Access Control: Pengecekan role tidak ketat)
// ============================================================================

app.get('/admin/users', requireAuth, (req, res) => {
  const user = req.user;
  const msg = req.query.msg || '';

  // KERENTANAN: Mahasiswa atau dosen bisa mengakses halaman ini jika mengetik URL!
  // Tidak ada pemeriksaan `if (user.role !== 'admin') return res.status(403)`
  const userList = db.prepare(`SELECT * FROM users ORDER BY role, id`).all();

  const userRows = userList.map((u, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td><strong>${u.username}</strong></td>
      <td>${u.full_name}</td>
      <td><span class="user-badge">${u.role}</span></td>
      <td>${u.identity_number}</td>
      <td>${u.email}</td>
      <td>${u.is_active ? '<span style="color:#16a34a;">Aktif</span>' : '<span style="color:#dc2626;">Non-aktif</span>'}</td>
      <td>
        <form method="POST" action="/admin/users/toggle" style="display:inline;">
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
      <p class="page-subtitle">Pengelolaan akun mahasiswa, dosen, dan staf pengajar</p>
    </div>

    ${msg ? `<div class="alert alert-success">${msg}</div>` : ''}

    <div class="card">
      <h3 class="card-title">Tambah Akun Baru</h3>
      <form method="POST" action="/admin/users/create">
        <div class="grid-2">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" required>
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="text" name="password" class="form-control" required>
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
        <button type="submit" class="btn btn-primary">Simpan Akun</button>
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

app.post('/admin/users/create', requireAuth, (req, res) => {
  const { username, password, full_name, role, identity_number, email } = req.body;
  // RENTAN: Password disimpan plaintext dan tanpa otorisasi admin
  db.prepare(`
    INSERT INTO users (username, password, full_name, role, identity_number, email)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(username, password, full_name, role, identity_number, email);
  res.redirect('/admin/users?msg=Pengguna+baru+berhasil+dibuat');
});

app.post('/admin/users/toggle', requireAuth, (req, res) => {
  const { user_id, current_status } = req.body;
  const newStatus = parseInt(current_status) === 1 ? 0 : 1;
  db.prepare(`UPDATE users SET is_active = ? WHERE id = ?`).run(newStatus, user_id);
  res.redirect('/admin/users?msg=Status+pengguna+berhasil+diubah');
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER RENTAN] Berjalan di http://localhost:${PORT}`);
  });
}

module.exports = app;
