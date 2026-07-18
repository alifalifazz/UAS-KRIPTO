# Clypher — Simulasi Algoritma Kriptografi

Aplikasi web simulasi enkripsi & dekripsi step-by-step untuk empat algoritma kriptografi simetris: **DES**, **S-DES**, **AES-128**, dan **S-AES**. Dibuat untuk memenuhi tugas UAS Mata Kuliah Kriptografi.

Setiap modul menampilkan seluruh tahapan perhitungan (pembentukan subkey, permutasi, substitusi S-Box, XOR, round function, dst) sehingga hasil aplikasi dapat diverifikasi langsung terhadap perhitungan manual.

---

## 1. Teknologi yang Digunakan

| Komponen | Teknologi |
|---|---|
| Struktur halaman | HTML5 |
| Tampilan | CSS3 (custom stylesheet, `css/style.css`) |
| Logika algoritma | JavaScript (vanilla) |

Aplikasi web ini **tidak memerlukan backend/server**, seluruh logika enkripsi-dekripsi berjalan di sisi klien (browser).

---

## 2. Struktur Folder

```
uas-kripto/
├── index.html            → Landing page (navigasi ke 4 modul)
├── README.md
├── css/
│   └── style.css         → Styling terpusat untuk seluruh halaman
├── js/
│   ├── common.js         → Helper bersama (konversi bit/hex, validasi, render step, wiring UI)
│   ├── des.js             → Logika inti DES + step tracing
│   ├── sdes.js            → Logika inti S-DES + step tracing
│   ├── aes.js              → Logika inti AES-128 + step tracing
│   └── saes.js            → Logika inti S-AES + step tracing
├── modules/
│   ├── des.html
│   ├── sdes.html
│   ├── aes.html
│   └── saes.html

```
### Cara Menjalankan
1. Buka folder `uas-kripto/` di Visual Studio Code.
2. Pasang ekstensi **Live Server**.
3. Klik kanan pada `index.html` → pilih **"Open with Live Server"**.
4. Browser akan otomatis terbuka ke alamat lokal ( `http://127.0.0.1:5500`).

## 3. Cara Menggunakan Setiap Modul

1. Buka salah satu modul dari menu navigasi: **DES / S-DES / AES / S-AES**.
2. Pilih mode **Enkripsi** atau **Dekripsi** melalui toggle di bagian atas form.
3. Isi form input:
   - **DES**: Plaintext/Ciphertext 64-bit dan Key 64-bit (boleh biner atau hex).
   - **S-DES**: Plaintext/Ciphertext 8-bit dan Key 10-bit (biner).
   - **AES-128**: Plaintext/Ciphertext 128-bit dan Key 128-bit (hex, 32 digit).
   - **S-AES**: Plaintext/Ciphertext 16-bit dan Key 16-bit (boleh biner atau hex).
   - Bisa juga klik tombol **"isi otomatis"** di bawah form untuk mengisi contoh kasus uji siap pakai.
4. Klik **Submit** untuk memproses. Hasil akhir akan muncul di kotak **Hasil**.
5. Klik **Tampilkan Solusi Penyelesaian** untuk membuka seluruh tahapan perhitungan (key generation, permutasi, substitusi, XOR, dsb). Setiap tahap bisa dibuka/ditutup satu per satu, atau gunakan **Buka semua / Tutup semua**.
6. Klik **Reset** untuk mengosongkan form dan mengulang dari awal.

---
## 4. Fitur Utama

- **Empat modul algoritma dalam satu aplikasi** — DES, S-DES, AES-128, dan S-AES, masing-masing dapat diakses dari landing page yang sama.
- **Mode Enkripsi & Dekripsi dua arah** — setiap modul mendukung kedua arah proses dengan penjadwalan subkey/round key yang benar untuk masing-masing arah.
- **Solusi penyelesaian step-by-step** — seluruh tahapan (key generation, permutasi, substitusi S-Box, XOR, round function, dsb) ditampilkan berurutan dalam accordion yang bisa dibuka/ditutup per langkah, atau sekaligus lewat tombol "Buka semua" / "Tutup semua".
- **Validasi input otomatis** — form memvalidasi panjang bit dan format (biner/hex) secara real-time, lengkap dengan pesan kesalahan yang jelas.
- **Input fleksibel (biner atau hex)** — pada modul yang mendukungnya (DES, S-AES), input plaintext/ciphertext dan key bisa diisi dalam bentuk biner maupun hex.
- **Kasus uji siap pakai** — tombol "isi otomatis" pada tiap modul untuk langsung mencoba contoh kasus uji yang sudah diverifikasi.
- **Hasil ditampilkan jelas** — output akhir ditampilkan sebagai teks, serta rincian per bit/byte dalam kotak-kotak kecil, dan bisa disalin dengan satu klik.
- **Tanpa backend/server** — seluruh proses enkripsi-dekripsi berjalan di browser (client-side); tidak ada data yang dikirim ke server mana pun.
- **Desain responsif** — tampilan menyesuaikan baik di desktop maupun mobile.

---