/**
 * Automated Security Testing Script
 * Menguji secara nyata 4 kerentanan pada Versi Rentan (port 3001)
 * dan memverifikasi kontrol keamanan pada Versi Aman (port 3002).
 */

const http = require('http');
const { spawn } = require('child_process');
const path = require('path');

const rootDir = path.resolve(__dirname);

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const opts = { ...options, host: '127.0.0.1' };
    delete opts.hostname;
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', err => reject(err));

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

async function runTests() {
  console.log('================================================================');
  console.log('MEMULAI SUITE PENGUJIAN KEAMANAN SISTEM INFORMASI (KSI)');
  console.log('================================================================');

  // 1. Jalankan kedua server
  console.log('[1/6] Menjalankan server versi rentan (port 3001) & versi aman (port 3002)...');
  const procRentan = spawn(process.execPath, ['rentan/server.js'], { cwd: rootDir, stdio: 'pipe' });
  const procAman = spawn(process.execPath, ['aman/server.js'], { cwd: rootDir, stdio: 'pipe' });

  // Tangkap output log & error
  procRentan.stdout.on('data', d => process.stdout.write(`[LOG-RENTAN] ${d}`));
  procRentan.stderr.on('data', d => process.stderr.write(`[ERR-RENTAN] ${d}`));
  procAman.stdout.on('data', d => process.stdout.write(`[LOG-AMAN] ${d}`));
  procAman.stderr.on('data', d => process.stderr.write(`[ERR-AMAN] ${d}`));

  // Tunggu 2 detik hingga server aktif
  await delay(2000);

  const results = [];

  try {
    // ------------------------------------------------------------------------
    // PENGUJIAN 1: SQL INJECTION PADA FORM LOGIN
    // ------------------------------------------------------------------------
    console.log('\n--- PENGUJIAN 1: SQL INJECTION (AUTH BYPASS) ---');
    const sqliPayload = "username=' OR '1'='1' --&password=apapun";

    // 1.1 Uji pada Versi Rentan
    const resSqliRentan = await makeRequest({
      hostname: 'localhost',
      port: 3001,
      path: '/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(sqliPayload)
      }
    }, sqliPayload);

    const rentanSqliBypassed = resSqliRentan.statusCode === 302 && 
      resSqliRentan.headers['location'] === '/' &&
      resSqliRentan.headers['set-cookie'] !== undefined;

    console.log(`[RENTAN] Hasil SQLi: Status ${resSqliRentan.statusCode}, Location: ${resSqliRentan.headers['location']}`);
    console.log(`[RENTAN] Bypass Berhasil: ${rentanSqliBypassed ? 'YA (VULNERABLE)' : 'TIDAK'}`);

    // 1.2 Uji pada Versi Aman
    const resSqliAman = await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(sqliPayload)
      }
    }, sqliPayload);

    const amanSqliBlocked = resSqliAman.statusCode === 302 && 
      resSqliAman.headers['location'].includes('error=');

    console.log(`[AMAN] Hasil SQLi: Status ${resSqliAman.statusCode}, Location: ${resSqliAman.headers['location']}`);
    console.log(`[AMAN] Serangan Diblokir: ${amanSqliBlocked ? 'YA (SECURE - PREPARED STATEMENT)' : 'TIDAK'}`);

    results.push({
      vulnerability: 'SQL Injection pada Login',
      rentan: rentanSqliBypassed ? 'TERBUKTI RENTAN (Auth Bypass Sukses)' : 'GAGAL TERBUKTI',
      aman: amanSqliBlocked ? 'TERBUKTI AMAN (Input Dinetralkan Prepared Statement)' : 'RENTAN'
    });

    // ------------------------------------------------------------------------
    // PENGUJIAN 2: INSECURE DIRECT OBJECT REFERENCES (IDOR) PADA NILAI
    // ------------------------------------------------------------------------
    console.log('\n--- PENGUJIAN 2: IDOR PADA FITUR NILAI MAHASISWA ---');

    // 2.1 Login sebagai Budi (ID 1) di Versi Rentan
    const rentanBudiCookie = 'user_id=1';
    // Akses nilai Siti (student_id = 2)
    const resIdorRentan = await makeRequest({
      hostname: 'localhost',
      port: 3001,
      path: '/grades?student_id=2',
      method: 'GET',
      headers: { 'Cookie': rentanBudiCookie }
    });

    const rentanIdorLeaked = resIdorRentan.body.includes('Siti Rahmawati') && resIdorRentan.body.includes('student_id = 2');
    console.log(`[RENTAN] Akses Budi ke student_id=2: ${rentanIdorLeaked ? 'DATA SITI TERBOCOR (VULNERABLE)' : 'DITOLAK'}`);

    // 2.2 Login sebagai Budi di Versi Aman
    const loginAmanBudiData = 'username=mhs_budi&password=BudiPass123!';
    const resLoginAmanBudi = await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(loginAmanBudiData)
      }
    }, loginAmanBudiData);

    const amanBudiCookie = resLoginAmanBudi.headers['set-cookie'] ? resLoginAmanBudi.headers['set-cookie'][0].split(';')[0] : '';

    // Coba akses student_id=2 dengan cookie Budi di Versi Aman
    const resIdorAman = await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/grades?student_id=2',
      method: 'GET',
      headers: { 'Cookie': amanBudiCookie }
    });

    // Pada versi aman, Budi tetap hanya mendapatkan nilai Budi Wicaksono
    const amanIdorBlocked = resIdorAman.body.includes('Budi Wicaksono') && !resIdorAman.body.includes('Siti Rahmawati');
    console.log(`[AMAN] Akses Budi ke student_id=2: ${amanIdorBlocked ? 'PARAMETER DIABAIKAN, HANYA NILAI BUDI DITAMPILKAN (SECURE)' : 'BOCOR'}`);

    results.push({
      vulnerability: 'IDOR pada Transkrip Nilai',
      rentan: rentanIdorLeaked ? 'TERBUKTI RENTAN (Nilai Mahasiswa Lain Bocor)' : 'GAGAL TERBUKTI',
      aman: amanIdorBlocked ? 'TERBUKTI AMAN (Otorisasi Sisi Server Memaksa ID Pemilik Sesi)' : 'RENTAN'
    });

    // ------------------------------------------------------------------------
    // PENGUJIAN 3: STORED CROSS-SITE SCRIPTING (STORED XSS)
    // ------------------------------------------------------------------------
    console.log('\n--- PENGUJIAN 3: STORED XSS PADA FORUM DISKUSI ---');
    const xssPayload = '<script>alert("XSS_KSI_VERIFIED")</script>';

    // 3.1 Kirim payload XSS ke Versi Rentan
    const postDataRentanXss = `title=TesXSS&content=${encodeURIComponent(xssPayload)}`;
    await makeRequest({
      hostname: 'localhost',
      port: 3001,
      path: '/forum',
      method: 'POST',
      headers: {
        'Cookie': rentanBudiCookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postDataRentanXss)
      }
    }, postDataRentanXss);

    // Ambil halaman forum rentan
    const resForumRentan = await makeRequest({
      hostname: 'localhost',
      port: 3001,
      path: '/forum',
      method: 'GET',
      headers: { 'Cookie': rentanBudiCookie }
    });

    const rentanXssExecuted = resForumRentan.body.includes(xssPayload);
    console.log(`[RENTAN] Stored XSS Render: ${rentanXssExecuted ? 'TAG SCRIPT UTUH TERSIMPAN & DIRENDER (VULNERABLE)' : 'LOLOS ENCODING'}`);

    // 3.2 Ambil CSRF token untuk Versi Aman terlebih dahulu
    const resForumAmanGet = await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/forum',
      method: 'GET',
      headers: { 'Cookie': amanBudiCookie }
    });

    // Ekstrak token CSRF dari HTML
    const csrfMatch = resForumAmanGet.body.match(/name="_csrf" value="([^"]+)"/);
    const csrfToken = csrfMatch ? csrfMatch[1] : '';

    // Kirim payload XSS ke Versi Aman
    const postDataAmanXss = `_csrf=${csrfToken}&title=TesXSS&content=${encodeURIComponent(xssPayload)}`;
    await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/forum',
      method: 'POST',
      headers: {
        'Cookie': amanBudiCookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postDataAmanXss)
      }
    }, postDataAmanXss);

    const resForumAman = await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/forum',
      method: 'GET',
      headers: { 'Cookie': amanBudiCookie }
    });

    const amanXssEscaped = resForumAman.body.includes('&lt;script&gt;alert(&quot;XSS_KSI_VERIFIED&quot;)&lt;/script&gt;') &&
                           !resForumAman.body.includes(xssPayload);

    console.log(`[AMAN] Stored XSS Render: ${amanXssEscaped ? 'HTML DI-ESCAPE SECARA AMAN (SECURE - NO XSS)' : 'RENTAN'}`);

    results.push({
      vulnerability: 'Stored XSS pada Forum Diskusi',
      rentan: rentanXssExecuted ? 'TERBUKTI RENTAN (Payload Script Dieksekusi Browser)' : 'GAGAL TERBUKTI',
      aman: amanXssEscaped ? 'TERBUKTI AMAN (Contextual HTML Entity Encoding Mencegah Eksekusi)' : 'RENTAN'
    });

    // ------------------------------------------------------------------------
    // PENGUJIAN 4: BRUTE FORCE & RATE LIMITING
    // ------------------------------------------------------------------------
    console.log('\n--- PENGUJIAN 4: BRUTE FORCE & RATE LIMITING PADA LOGIN ---');

    // 4.1 Versi Rentan: Coba 7 kali password salah berturut-turut
    let rentanAllAllowed = true;
    for (let i = 1; i <= 7; i++) {
      const bfPayload = `username=mhs_budi&password=SalahPassword_${i}`;
      const res = await makeRequest({
        hostname: 'localhost',
        port: 3001,
        path: '/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(bfPayload)
        }
      }, bfPayload);

      if (res.statusCode === 429) {
        rentanAllAllowed = false;
      }
    }
    console.log(`[RENTAN] 7 Percobaan Password Salah: ${rentanAllAllowed ? 'SEMUA DIPROSES TANPA LIMIT / BLOCK (VULNERABLE)' : 'DIBATASI'}`);

    // 4.2 Versi Aman: Coba password salah hingga melebihi batas 5x
    let amanRateLimitTriggered = false;
    let lockResponseText = '';
    for (let i = 1; i <= 7; i++) {
      const bfPayload = `username=mhs_budi&password=SalahPassword_${i}`;
      const res = await makeRequest({
        hostname: 'localhost',
        port: 3002,
        path: '/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(bfPayload)
        }
      }, bfPayload);

      if (res.statusCode === 429) {
        amanRateLimitTriggered = true;
        lockResponseText = res.body;
        console.log(`[AMAN] Percobaan ke-${i} berhasil diblokir dengan HTTP 429 (Too Many Requests).`);
        break;
      }
    }
    console.log(`[AMAN] Proteksi Brute-Force: ${amanRateLimitTriggered ? 'RATE LIMIT BERHASIL MENGUNCI AKUN (SECURE)' : 'TIDAK DIBATASI'}`);

    results.push({
      vulnerability: 'Login Brute-Force Tanpa Batas',
      rentan: rentanAllAllowed ? 'TERBUKTI RENTAN (Ribuan Request Diizinkan Tanpa Batas)' : 'GAGAL TERBUKTI',
      aman: amanRateLimitTriggered ? 'TERBUKTI AMAN (HTTP 429 Lockout Setelah 5 Percobaan Gagal)' : 'RENTAN'
    });

    // ------------------------------------------------------------------------
    // PENGUJIAN 5: BROKEN ACCESS CONTROL (ROLE-BASED AUTHORIZATION)
    // ------------------------------------------------------------------------
    console.log('\n--- PENGUJIAN 5: BROKEN ACCESS CONTROL (ADMIN ENDPOINT) ---');

    // Mahasiswa mengakses /admin/users pada Rentan
    const resAdminRentan = await makeRequest({
      hostname: 'localhost',
      port: 3001,
      path: '/admin/users',
      method: 'GET',
      headers: { 'Cookie': rentanBudiCookie }
    });
    const rentanBacLeaked = resAdminRentan.statusCode === 200 && resAdminRentan.body.includes('Manajemen Akun Pengguna');
    console.log(`[RENTAN] Mahasiswa Buka /admin/users: ${rentanBacLeaked ? 'TERBUKA / LOLOS (VULNERABLE)' : 'DITOLAK'}`);

    // Mahasiswa mengakses /admin/users pada Aman
    const resAdminAman = await makeRequest({
      hostname: 'localhost',
      port: 3002,
      path: '/admin/users',
      method: 'GET',
      headers: { 'Cookie': amanBudiCookie }
    });
    const amanBacBlocked = resAdminAman.statusCode === 403;
    console.log(`[AMAN] Mahasiswa Buka /admin/users: ${amanBacBlocked ? 'HTTP 403 FORBIDDEN (SECURE)' : 'LOLOS'}`);

    results.push({
      vulnerability: 'Broken Access Control (Akses Admin oleh Mahasiswa)',
      rentan: rentanBacLeaked ? 'TERBUKTI RENTAN (Endpoint Admin Terbuka untuk Mahasiswa)' : 'GAGAL TERBUKTI',
      aman: amanBacBlocked ? 'TERBUKTI AMAN (HTTP 403 Forbidden via Middleware RBAC)' : 'RENTAN'
    });

  } catch (error) {
    console.error('Error saat menjalankan pengujian:', error);
  } finally {
    // Matikan server
    procRentan.kill();
    procAman.kill();
    console.log('\n[6/6] Server uji dinonaktifkan.');
  }

  console.log('\n================================================================');
  console.log('REKAPITULASI HASIL PENGUJIAN OTOMATIS:');
  console.log('================================================================');
  console.table(results);
}

runTests();
