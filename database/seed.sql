-- ====================================================================
-- DATA AWAL SINTETIS (SEED): PORTAL AKADEMIK FIKTIF
-- Seluruh entitas di bawah ini fiktif untuk praktikum keamanan lokal
-- ====================================================================

-- 1. Kursus / Mata Kuliah Fiktif
INSERT INTO courses (id, code, name, credits, lecturer_id) VALUES
(1, 'KSI301', 'Keamanan Sistem Informasi', 3, 3),
(2, 'JARKOM201', 'Jaringan Komputer Lanjut', 3, 3),
(3, 'BASDAT101', 'Sistem Basis Data', 3, 3);

-- 2. Nilai Fiktif Mahasiswa
INSERT INTO grades (student_id, course_id, assignment_score, mid_score, final_score, letter_grade) VALUES
(1, 1, 85.0, 80.0, 88.0, 'A'),
(1, 2, 78.0, 75.0, 82.0, 'B+'),
(2, 1, 95.0, 92.0, 96.0, 'A'),
(2, 3, 90.0, 88.0, 91.0, 'A');

-- 3. Tugas Awal Fiktif
INSERT INTO assignments (student_id, course_id, title, file_path, original_filename, score, feedback) VALUES
(1, 1, 'Tugas 1: Analisis Kriptografi Klasik', 'sample_tugas1_budi.pdf', 'tugas1_budi.pdf', 85.0, 'Analisis substitusi cipher sudah tepat.'),
(2, 1, 'Tugas 1: Analisis Model Keamanan CIA', 'sample_tugas1_siti.pdf', 'tugas1_siti.pdf', 95.0, 'Pembahasan mendalam dan referensi relevan.');

-- 4. Postingan Forum Awal
INSERT INTO forum_posts (user_id, title, content) VALUES
(3, 'Pengantar Praktikum Keamanan Web', 'Selamat datang di forum praktikum. Silakan gunakan forum ini untuk berdiskusi seputar materi perkuliahan dan tugas mingguan.'),
(2, 'Pertanyaan Format Laporan Tugas', 'Selamat siang Pak Hendra, izin bertanya apakah laporan praktikum dikumpulkan dalam format PDF standar IEEE atau bebas? Terima kasih.');
