<div align="center">

# 🕵️ Dayı Stego Solver

### Automated steganography and file-forensics triage for CTFs

**Give Dayı a suspicious file. It identifies the format, routes it through a bounded 22-plugin pipeline, extracts artifacts, looks for flags, and writes a report.**

[![Python 3.10–3.13](https://img.shields.io/badge/Python-3.10%E2%80%933.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![CI](https://github.com/MacallanTheRoot/DayiStegoSolver/actions/workflows/ci.yml/badge.svg)](https://github.com/MacallanTheRoot/DayiStegoSolver/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MacallanTheRoot/DayiStegoSolver)](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Core Dependencies](https://img.shields.io/badge/Core%20Dependencies-stdlib-brightgreen)](pyproject.toml)

**English** · [Türkçe](#-türkçe-dokümantasyon)

[Latest release](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/tag/v4.5.1) ·
[Installation](#installation) ·
[Quick start](#quick-start) ·
[Supported analysis](#what-it-analyzes) ·
[Security model](#security-model)

*"Hallederiz yeğenim."*

</div>

---

## English Documentation

## Why Dayı?

Steganography challenges often require manually trying several unrelated tools:

```text
file → exiftool → strings → binwalk → zsteg → steghide → stegseek → OCR → custom scripts
```

Dayı coordinates that workflow from one CLI while keeping analysis local, bounded, and deterministic.

```bash
dayi scan challenge.png
```

It can:

- detect the real file type from content instead of trusting the extension;
- run only relevant tools and built-in analyzers;
- inspect image, text, archive, document, PDF, OLE/macro, QR, and PCAP evidence;
- decode nested text and collect contextual password candidates;
- attribute discovered flags to the plugin that found them;
- write a Markdown report;
- optionally notify CTFd or Discord.

> Dayı is a triage and automation tool, not a guarantee that every challenge will be solved automatically.

---

## Installation

### Core installation

```bash
git clone https://github.com/MacallanTheRoot/DayiStegoSolver.git
cd DayiStegoSolver

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .

dayi --version
dayi doctor
```

The core package uses the Python standard library and remains usable when optional tools are missing.

### Recommended optional Python features

```bash
python -m pip install -e ".[ui,ocr,qr,pdf,ole,pcap,integration]"
```

### Recommended system tools on Kali, Debian, or Ubuntu

```bash
sudo apt update
sudo apt install -y \
  libimage-exiftool-perl \
  exiv2 \
  binutils \
  binwalk \
  steghide \
  outguess \
  tesseract-ocr

sudo gem install zsteg
```

Install StegSeek from its official releases:

```bash
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

Check the environment:

```bash
dayi doctor
dayi plugins list
```

---

## Quick start

```bash
# Built-in common flag patterns
dayi scan challenge.png

# Challenge-specific flag expression
dayi scan challenge.jpg --flag 'CTF\{.*?\}'

# Extensionless or misleading file
dayi scan hidden.data --flag 'SiberVatan\{.*?\}' -v

# Health and plugin diagnostics
dayi doctor
dayi plugins list
```

---

## What it analyzes

| Area | Coverage |
|---|---|
| **Images** | JPEG, PNG, BMP, GIF, TIFF, WebP, PNM; metadata, strings, embedded files, LSB-oriented analysis, OCR, and QR |
| **Text steganography** | Bacon, whitespace, zero-width Unicode, homoglyphs, acrostic and structural channels, ghost text, Hex/Base64 nesting |
| **Documents** | DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, ODT/ODS/ODP, and RTF concealment, metadata, comments, relationships, media, and embedded objects |
| **Archives** | ZIP discovery, bounded extraction, extensionless ZIP carving, contextual password attempts, streamed wordlists |
| **PDF** | Metadata, bounded page text, empty-password encrypted documents, flags, and passive artifacts |
| **OLE and macros** | Bounded VBA source extraction from supported OLE and OpenXML containers |
| **PCAP/PCAPNG** | Streamed Raw, ICMP, DNS, HTTP, flags, passive artifacts, and bounded carving of recognized payloads |
| **Passive artifacts** | URLs, IP addresses, conservative domains, credential hints, coordinates, and printable encoded hints |

### Registered pipeline

Dayı 4.5.1 ships with:

- **22 registered plugins**
- **12 concurrent-phase operations**
- dynamic plugin discovery and validation
- clean degradation when optional runtimes are unavailable

Common integrations:

```text
exiftool · exiv2 · strings · binwalk · zsteg · steghide
stegseek · outguess · Tesseract · OpenCV/pyzbar/zbarimg
pypdf · oletools · Scapy
```

---

## Example workflow

```text
[+] Target type: PNG
[+] Running relevant metadata, archive, LSB, QR, and OCR analysis
[+] Extracted printable Base64 candidate
[+] Decoded nested text
[FLAG] CTF{example_flag}
[+] Found by: strings, text_stego_scanner
[+] Markdown report written
```

Actual output depends on installed optional tools and the analyzed challenge.

---

## Design principles

- **Content-based routing:** file signatures are preferred over filename extensions.
- **Bounded execution:** parsers, archives, OCR, documents, packets, recursion, and subprocesses have explicit limits.
- **Passive by default:** discovered URLs and commands are reported, not opened or executed.
- **No active document content:** macros, formulas, fields, embedded executables, and external relationships are never executed or fetched.
- **Deterministic reporting:** plugin order, attribution, and JSON-capable diagnostics support repeatable runs.
- **Graceful degradation:** missing optional tools reduce coverage without breaking the core CLI.

---

## Security model

Dayı processes untrusted CTF files, so analysis is deliberately constrained. It rejects or limits path traversal, symlink escapes, decompression bombs, oversized archive members, excessive image dimensions, oversized OCR/PDF/Office/RTF/PCAP inputs, recursive decoding, unsafe terminal control data, and lingering subprocesses after timeouts.

No local forensic tool can provide a complete sandbox guarantee. Use a disposable VM or container for unknown files and keep third-party tools updated.

---

## Reports and integrations

Dayı writes a built-in Markdown report. It can optionally:

- use a validated `csl-ctfshitcli` installation for richer writeups;
- submit discovered flags to a configured CTFd instance;
- send independent Discord notifications.

---

## Release status

**Latest stable release: [v4.5.1](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/tag/v4.5.1)**

- Python: 3.10–3.13
- CI: passing across all supported Python versions
- Distribution: verified wheel and source archive
- License: MIT

Release checksums are included with the GitHub Release assets.

---

## Roadmap

- public CTF challenge benchmark;
- reproducible demonstration corpus;
- installation and Docker experience;
- shorter visual documentation;
- community feedback and external contributions.

---

## Contributing

Issues and focused pull requests are welcome. Useful contributions include reproducible public challenge samples, false-positive or missed-detection reports, new bounded analyzers, portability fixes, installation documentation, and benchmark results.

Do not submit private challenge data, credentials, or copyrighted corpora without redistribution permission.

---

## License

Released under the [MIT License](LICENSE).

---

## Türkçe Dokümantasyon

## Dayı nedir?

Steganografi challenge'larında çoğu zaman birbirinden bağımsız birçok aracı elle denemek gerekir:

```text
dosya → exiftool → strings → binwalk → zsteg → steghide → stegseek → OCR → özel scriptler
```

Dayı bu akışı tek bir CLI altında koordine eder. Analizi yerel, sınırlı ve deterministik tutar.

```bash
dayi scan challenge.png
```

Dayı şunları yapabilir:

- dosya uzantısına güvenmek yerine gerçek dosya türünü içerikten algılar;
- yalnız ilgili araçları ve dahili analiz modüllerini çalıştırır;
- görsel, metin, arşiv, doküman, PDF, OLE/makro, QR ve PCAP kanıtlarını inceler;
- iç içe kodlanmış metinleri çözer ve bağlamsal parola adayları toplar;
- bulunan flag'i hangi pluginin bulduğunu raporlar;
- Markdown raporu oluşturur;
- isteğe bağlı olarak CTFd veya Discord bildirimi gönderir.

> Dayı bir triage ve otomasyon aracıdır; her challenge'ı otomatik çözeceği garanti edilmez.

---

## Kurulum

### Core kurulum

```bash
git clone https://github.com/MacallanTheRoot/DayiStegoSolver.git
cd DayiStegoSolver

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .

dayi --version
dayi doctor
```

Core paket Python standart kütüphanesiyle çalışır. Optional araçlar eksik olsa bile temel CLI kullanılabilir.

### Önerilen optional Python özellikleri

```bash
python -m pip install -e ".[ui,ocr,qr,pdf,ole,pcap,integration]"
```

### Kali, Debian veya Ubuntu için önerilen sistem araçları

```bash
sudo apt update
sudo apt install -y \
  libimage-exiftool-perl \
  exiv2 \
  binutils \
  binwalk \
  steghide \
  outguess \
  tesseract-ocr

sudo gem install zsteg
```

StegSeek'i resmi release üzerinden kur:

```bash
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

Ortamı kontrol et:

```bash
dayi doctor
dayi plugins list
```

---

## Hızlı başlangıç

```bash
# Dahili genel flag patternleri
dayi scan challenge.png

# Challenge'a özel flag ifadesi
dayi scan challenge.jpg --flag 'CTF\{.*?\}'

# Uzantısız veya yanıltıcı uzantılı dosya
dayi scan hidden.data --flag 'SiberVatan\{.*?\}' -v

# Sağlık ve plugin kontrolleri
dayi doctor
dayi plugins list
```

---

## Neleri analiz eder?

| Alan | Kapsam |
|---|---|
| **Görseller** | JPEG, PNG, BMP, GIF, TIFF, WebP, PNM; metadata, strings, embedded dosyalar, LSB odaklı analiz, OCR ve QR |
| **Metin steganografisi** | Bacon, whitespace, zero-width Unicode, homoglyph, acrostic ve yapısal kanallar, ghost text, iç içe Hex/Base64 |
| **Dokümanlar** | DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, ODT/ODS/ODP ve RTF gizleme yöntemleri, metadata, yorumlar, ilişkiler, medya ve embedded objeler |
| **Arşivler** | ZIP keşfi, sınırlı extraction, uzantısız ZIP carving, bağlamsal parola denemeleri, streamed wordlist |
| **PDF** | Metadata, sınırlı sayfa metni, boş parolalı şifreli belgeler, flag ve pasif artifact taraması |
| **OLE ve makrolar** | Desteklenen OLE ve OpenXML container'lardan sınırlı VBA source extraction |
| **PCAP/PCAPNG** | Streamed Raw, ICMP, DNS, HTTP, flag, pasif artifact ve tanınan payload carving |
| **Pasif artifact'ler** | URL, IP, kontrollü domain, credential hint, koordinat ve yazdırılabilir encoded hint |

### Kayıtlı pipeline

Dayı 4.5.1:

- **22 kayıtlı plugin**
- **12 CONCURRENT aşama işlemi**
- dinamik plugin keşfi ve doğrulama
- optional runtime eksik olduğunda temiz degradation

Yaygın entegrasyonlar:

```text
exiftool · exiv2 · strings · binwalk · zsteg · steghide
stegseek · outguess · Tesseract · OpenCV/pyzbar/zbarimg
pypdf · oletools · Scapy
```

---

## Örnek çalışma akışı

```text
[+] Hedef türü: PNG
[+] İlgili metadata, arşiv, LSB, QR ve OCR analizleri başlatıldı
[+] Yazdırılabilir Base64 adayı çıkarıldı
[+] İç içe metin çözüldü
[FLAG] CTF{example_flag}
[+] Bulan pluginler: strings, text_stego_scanner
[+] Markdown raporu yazıldı
```

Gerçek çıktı, kurulu optional araçlara ve analiz edilen challenge'a göre değişir.

---

## Tasarım ilkeleri

- **İçerik tabanlı yönlendirme:** dosya imzaları, dosya uzantısından önce gelir.
- **Sınırlı çalışma:** parser, arşiv, OCR, doküman, paket, recursion ve subprocess işlemleri açık limitlere sahiptir.
- **Varsayılan olarak pasif:** bulunan URL ve komutlar raporlanır; açılmaz veya çalıştırılmaz.
- **Aktif doküman içeriği yok:** makro, formül, field, embedded executable ve external relationship çalıştırılmaz veya fetch edilmez.
- **Deterministik raporlama:** plugin sırası, attribution ve JSON diagnostic çıktıları tekrarlanabilir çalışmayı destekler.
- **Temiz degradation:** optional araçların eksikliği core CLI'yi bozmaz.

---

## Güvenlik modeli

Dayı güvenilmeyen CTF dosyalarını işler. Bu nedenle path traversal, symlink escape, decompression bomb, büyük arşiv üyeleri, aşırı görsel boyutları, büyük OCR/PDF/Office/RTF/PCAP girdileri, kontrolsüz recursive decoding, terminal control karakterleri ve timeout sonrası kalan subprocess'ler sınırlandırılır veya reddedilir.

Hiçbir yerel forensics aracı tam sandbox garantisi vermez. Bilinmeyen dosyaları disposable VM veya container içinde analiz et ve üçüncü taraf araçları güncel tut.

---

## Raporlar ve entegrasyonlar

Dayı yerleşik Markdown raporu üretir. İsteğe bağlı olarak:

- daha zengin writeup için doğrulanmış `csl-ctfshitcli` kurulumu kullanabilir;
- bulunan flag'leri yapılandırılmış CTFd sunucusuna gönderebilir;
- bağımsız Discord bildirimi gönderebilir.

---

## Sürüm durumu

**Son kararlı sürüm: [v4.5.1](https://github.com/MacallanTheRoot/DayiStegoSolver/releases/tag/v4.5.1)**

- Python: 3.10–3.13
- CI: desteklenen tüm Python sürümlerinde başarılı
- Dağıtım: doğrulanmış wheel ve source archive
- Lisans: MIT

Release checksum dosyaları GitHub Release asset'leri içinde bulunur.

---

## Yol haritası

- kamuya açık CTF challenge benchmark'ı;
- tekrar üretilebilir demo corpus'u;
- kurulum ve Docker deneyimi;
- daha kısa ve görsel dokümantasyon;
- topluluk geri bildirimi ve dış katkılar.

---

## Katkıda bulunma

Issue ve odaklı pull request'ler kabul edilir. Özellikle tekrar üretilebilir kamuya açık challenge örnekleri, false-positive veya missed-detection raporları, yeni bounded analyzer'lar, portability düzeltmeleri, kurulum dokümanı ve benchmark sonuçları değerlidir.

Dağıtım izni olmayan özel challenge verisi, credential veya copyrighted corpus eklemeyin.

---

## Lisans

Proje [MIT License](LICENSE) altında yayımlanır.

---

<div align="center">

Developed by [MacallanTheRoot](https://github.com/MacallanTheRoot)

**Dayı finds the evidence. You solve the challenge.**

</div>
