# 🔍 ReconLens

Ekstensi Chrome untuk **information gathering pasif**. Menganalisis setiap situs yang Anda buka: teknologi, security header, cookie, domain pihak ketiga, recon halaman, dan domain intel opsional. Semua analisis berjalan lokal di browser.

[English version](README.md)

## Instalasi
1. `git clone https://github.com/YOUR_USERNAME/reconlens.git`
2. Buka `chrome://extensions`, aktifkan **Developer mode**
3. **Load unpacked**, pilih folder hasil clone
4. Buka situs, **muat ulang halaman sekali**, lalu klik ikon ReconLens

## Fitur
Fingerprinting teknologi, audit security header (skor A–F), analisis cookie, peta pihak ketiga, recon halaman (form, email, endpoint dari JS, dugaan secret, robots/sitemap/security.txt), domain intel opsional (DNS, SPF/DMARC, RDAP, crt.sh), serta ekspor JSON/Markdown.

## Privasi
Tanpa telemetri. Request tambahan hanya: file well-known ke situs yang sedang dibuka (bisa dimatikan) dan Domain Intel saat tombol ditekan.

## Penggunaan yang bertanggung jawab
Alat ini pasif dan tidak melakukan scanning atau eksploitasi. Gunakan hanya pada situs milik sendiri atau yang Anda berwenang untuk analisis.

Lisensi: MIT.
