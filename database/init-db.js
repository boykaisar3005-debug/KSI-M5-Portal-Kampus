/**
 * Skrip Inisialisasi Database Terisolasi:
 * 1. database/rentan.sqlite (Versi Rentan)
 * 2. database/aman.sqlite (Versi Aman)
 */

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');

const dbDir = path.join(__dirname);
const rootDir = path.join(__dirname, '..');
const schemaSql = fs.readFileSync(path.join(dbDir, 'schema.sql'), 'utf-8');
const seedSql = fs.readFileSync(path.join(dbDir, 'seed.sql'), 'utf-8');

// Akun sintetis
const usersRentan = [
  { id: 1, username: 'mhs_budi', pass: 'BudiPass123!', name: 'Budi Wicaksono', role: 'mahasiswa', idNum: '20240101', email: 'budi.wicaksono@student.itsn-fiktif.ac.id' },
  { id: 2, username: 'mhs_siti', pass: 'SitiPass123!', name: 'Siti Rahmawati', role: 'mahasiswa', idNum: '20240102', email: 'siti.rahmawati@student.itsn-fiktif.ac.id' },
  { id: 3, username: 'dosen_hendra', pass: 'DosenPass123!', name: 'Dr. Hendra Pratama, M.Kom.', role: 'dosen', idNum: '198502012010121001', email: 'hendra.pratama@itsn-fiktif.ac.id' },
  { id: 4, username: 'admin_fajar', pass: 'AdminPass123!', name: 'Fajar Administrator', role: 'admin', idNum: 'ADM001', email: 'admin@itsn-fiktif.ac.id' }
];

function initDatabase(targetFile, isAman = false) {
  const fullPath = path.join(dbDir, targetFile);
  if (fs.existsSync(fullPath)) {
    fs.unlinkSync(fullPath);
  }

  const db = new DatabaseSync(fullPath);

  // Jalankan skema
  db.exec(schemaSql);

  // Masukkan pengguna
  const insertUser = db.prepare(`
    INSERT INTO users (id, username, password, full_name, role, identity_number, email)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const u of usersRentan) {
    const finalPassword = isAman ? bcrypt.hashSync(u.pass, 10) : u.pass;
    insertUser.run(u.id, u.username, finalPassword, u.name, u.role, u.idNum, u.email);
  }

  // Jalankan seed tambahan (courses, grades, assignments, forum_posts)
  db.exec(seedSql);

  console.log(`[OK] Basis data '${targetFile}' berhasil diinisialisasi (${isAman ? 'Aman - Bcrypt Hashed' : 'Rentan - Plaintext'}).`);
}

// Inisialisasi kedua database terisolasi
console.log('--- Memulai Inisialisasi Basis Data Praktikum KSI ---');
initDatabase('rentan.sqlite', false);
initDatabase('aman.sqlite', true);

// Buat file dummy tugas di folder uploads
const sampleFiles = ['sample_tugas1_budi.pdf', 'sample_tugas1_siti.pdf'];
const dirs = [
  path.join(rootDir, 'rentan', 'uploads'),
  path.join(rootDir, 'aman', 'uploads')
];

dirs.forEach(d => {
  if (!fs.existsSync(d)) {
    fs.mkdirSync(d, { recursive: true });
  }
  sampleFiles.forEach(fileName => {
    const fPath = path.join(d, fileName);
    if (!fs.existsSync(fPath)) {
      fs.writeFileSync(fPath, `%PDF-1.4\n% Contoh file tugas fiktif mahasiswa untuk pengujian laboratorium KSI.\n`);
    }
  });
});

console.log('[OK] Folder upload dan file sampel fiktif siap.');
