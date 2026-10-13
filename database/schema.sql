-- ====================================================================
-- SKEMA BASIS DATA: PORTAL AKADEMIK FIKTIF "SIAKAD NUSANTARA"
-- Laboratorium Praktikum Keamanan Sistem Informasi (KSI)
-- ====================================================================

-- Tabel 1: Pengguna (Mahasiswa, Dosen, Admin)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password TEXT NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('mahasiswa', 'dosen', 'admin')),
    identity_number VARCHAR(30) NOT NULL, -- NIM untuk Mhs, NIP untuk Dosen, ID Pegawai untuk Admin
    email VARCHAR(100) NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tabel 2: Mata Kuliah
CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(15) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    credits INTEGER NOT NULL,
    lecturer_id INTEGER,
    FOREIGN KEY (lecturer_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Tabel 3: Nilai Akademik Mahasiswa
CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    assignment_score REAL DEFAULT 0,
    mid_score REAL DEFAULT 0,
    final_score REAL DEFAULT 0,
    letter_grade VARCHAR(2) DEFAULT 'E',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

-- Tabel 4: Pengumpulan Tugas Mahasiswa
CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    title VARCHAR(150) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    score REAL DEFAULT NULL,
    feedback TEXT DEFAULT NULL,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

-- Tabel 5: Forum Diskusi
CREATE TABLE IF NOT EXISTS forum_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title VARCHAR(150) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabel 6: Catatan Percobaan Login (Untuk audit dan deteksi brute force)
CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'SUCCESS' atau 'FAILED'
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
);
