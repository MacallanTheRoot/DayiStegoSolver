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

### Advanced local analysis

The core `text_stego_scanner` works from detected text rather than filename
extensions. It scores zero-width Unicode, letter-case binary ASCII,
whitespace/SNOW, Bacon-style, homoglyph, acrostic/structural, ghost-text, and
nested Hex/Base64 candidates. Findings keep their plugin and decoder-chain
attribution. Analysis runs without network access; decoded content is data and
is never executed. ANSI/bidi/control characters are escaped before display.

Text analysis accepts at most **8 MiB** of source data, examines at most **4
million** decoded characters, retains at most **512 candidates**, limits each
candidate output to **64 KiB**, follows nested decoding to **depth 3**, and caps
aggregate decoded data at **16 MiB**.

Document analysis covers PDF, OpenXML/Office packages (DOCX/DOCM, XLSX/XLSM,
PPTX/PPTM), OLE/legacy documents when the optional parser supports them,
OpenDocument (ODT/ODS/ODP), RTF, and plain text routed to the appropriate local
analyzer. The `document_stego_scanner` inspects hidden styles, comments,
revisions, headers/footers, alt text, metadata, relationships, media, and
embedded objects. External relationships are reported only; macros, formulas,
fields, scripts, and embedded executables are never run or fetched.

OpenXML processing caps packages at **128 MiB**, members at **5,000**, each
member at **32 MiB**, aggregate uncompressed data at **256 MiB**, and each XML
member at **16 MiB**. Extraction caps media at **100**, embedded objects at
**50**, and recursive document traversal at **depth 3**. Results retain package
member and mechanism attribution. These analyzers are heuristic and
format/corpus dependent; they do not claim complete rendering or legacy-format
compatibility.

### OCR and QR controls

Use `--ocr-lang` to select installed Tesseract languages and
`--ocr-exhaustive` for the slower bounded preprocessing schedule. OCR remains
heuristic: stylized, damaged, or low-contrast text may not decode. The schedule
accepts at most 20 source images, 20 variants and 30 invocations per image, and
**200 OCR invocations** overall. Each invocation is limited to **15 seconds**
and 1 MiB of text; aggregate OCR text is capped at 8 MiB. A source image is
limited to 64 MiB and 50 million decoded pixels. Large exhaustive inputs may
need a plugin timeout of 60 seconds or more, for example `--timeout 60`.

The passive `qr_scanner` uses OpenCV, pyzbar, and zbarimg backends when
available. Decoded QR URLs, commands, archives, and embedded data are reported
or analyzed within existing limits but are never opened, fetched, or executed.
The registered pipeline remains **22 registered plugins**, including **12
concurrent plugins**.

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

Configuration is selected independently for each field: an explicit CLI value
wins over a nonblank environment value, followed by the default or disabled
state.

| Purpose | CLI option | Environment variable |
|---|---|---|
| CTFd base URL | `--ctfd-url` | `DAYI_CTFD_URL` |
| CTFd API token | `--ctfd-token` | `DAYI_CTFD_TOKEN` |
| CTFd challenge ID | `--challenge-id` | `DAYI_CTFD_CHALLENGE_ID` |
| Discord webhook | `--webhook` | `DAYI_DISCORD_WEBHOOK_URL` |
| Notification challenge name | `--challenge-name` | `DAYI_CHALLENGE_NAME` |
| Optional writeup checkout | `--ctfshit-path` | `DAYI_CTFSHIT_PATH` |

Prefer environment variables for secrets. Real tokens and webhook URLs must not
be placed in process listings, shell history, terminal logs, screenshots, or
committed files. The following values are deliberately non-secret placeholders:

```bash
export DAYI_CTFD_URL=https://ctfd.example
export DAYI_CTFD_TOKEN=TOKEN_REDACTED
export DAYI_CTFD_CHALLENGE_ID=42
export DAYI_DISCORD_WEBHOOK_URL=https://discord.example/webhook
export DAYI_CHALLENGE_NAME="Example challenge"
dayi scan challenge.jpg

# A CLI value overrides only its corresponding environment field.
dayi scan challenge.jpg --challenge-id 43

# Optional rich writeup checkout; built-in Markdown remains the fallback.
export DAYI_CTFSHIT_PATH=/path/to/local/ctfshitcli
dayi scan challenge.jpg --writeup writeup.md

# Network-free diagnostics
dayi doctor
dayi doctor --json
```

At manager creation Dayı selects usable aiohttp, otherwise stdlib urllib; that
transport selection is fixed for the scan. CTFd and Discord are dispatched
independently, and an integration failure never invalidates a completed scan.
`csl-ctfshitcli` is used only for rich Markdown writeups; Discord and CTFd do
not depend on it, and built-in Markdown is the writeup fallback.

Discord webhook URLs require HTTPS. CTFd HTTP remains accepted for backward
compatibility, although HTTPS is recommended. URL userinfo, query strings, and
fragments are rejected, redirects are blocked, requests use bounded timeouts,
and CTFd response reads are bounded. `dayi doctor` validates local configuration
only; it does not test endpoints, credentials, or reachability. Notification
secrets are not added to TXT, JSON, or Markdown reports.

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

### Local private regression

Private corpora, manifests, and reports must stay outside this repository.
Never commit challenge samples or exact flags, and redact filenames, paths,
payloads, and flag values from public reports. Real private regressions remain
read-only and local; deterministic synthetic fixtures are required for code
changes committed to the repository.

The local harness is explicitly bounded, uses no network access, and keeps
networking configuration disabled:

```bash
export DAYI_PRIVATE_CORPUS=/path/outside/repository/corpus
python scripts/run_private_regression.py \
  --input "$DAYI_PRIVATE_CORPUS" \
  --output /tmp/dayi-private-regression \
  --manifest /path/outside/repository/expectations.json \
  --timeout 180 --max-files 500 --anonymize --redact-flags
```

Use `--show-flags` only for an explicitly local report. The harness classifies
timeouts, parser failures, unsupported inputs, and missing tools separately;
its exit status reports harness/configuration failure rather than how many
challenges were solved. It does not execute decoded payloads. Synthetic tests
are required for fixes; private challenge data must never become a fixture.

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

### Gelişmiş yerel analiz

Çekirdek `text_stego_scanner`, dosya uzantısı yerine algılanan metin üzerinde
çalışır. Zero-width Unicode, harf büyüklüğüne dayalı binary ASCII,
whitespace/SNOW, Bacon-style, homoglyph, akrostiş/yapısal, ghost-text ve iç içe
Hex/Base64 adaylarını puanlar. Bulgular plugin ve decoder-chain attribution
bilgisini korur. Analiz ağ erişimi olmadan çalışır; çözülen içerik veri olarak
kalır ve çalıştırılmaz. ANSI/bidi/control karakterleri gösterimden önce escape
edilir.

Metin analizi en fazla **8 MiB** kaynak, **4 milyon** decoded karakter ve **512
aday** işler; aday çıktısını **64 KiB**, iç içe çözmeyi **depth 3** ve toplam
decoded veriyi **16 MiB** ile sınırlar.

Belge analizi PDF, OpenXML/Office paketleri (DOCX/DOCM, XLSX/XLSM, PPTX/PPTM),
optional parser desteklediğinde OLE/eski belgeler, OpenDocument (ODT/ODS/ODP),
RTF ve uygun yerel analizöre yönlendirilen düz metni kapsar.
`document_stego_scanner`; gizli stiller, yorumlar, revizyonlar, header/footer,
alt text, metadata, ilişkiler, medya ve gömülü nesneleri inceler. Harici
ilişkiler yalnızca raporlanır; makrolar, formüller, field'lar, scriptler ve
gömülü executable'lar çalıştırılmaz veya fetch edilmez.

OpenXML işlemleri paketleri **128 MiB**, üyeleri **5.000**, her üyeyi **32 MiB**,
toplam açılmış veriyi **256 MiB** ve her XML üyesini **16 MiB** ile sınırlar.
Extraction sırasında medya sayısı **100**, gömülü nesne sayısı **50** ve recursive
belge geçişi **depth 3** ile sınırlıdır. Bulgular paket üyesi ve mekanizma
attribution bilgisini korur. Bu analizler heuristic ve format/corpus bağımlıdır;
eksiksiz render veya eski-format uyumluluğu iddia etmez.

### OCR ve QR kontrolleri

Kurulu Tesseract dillerini `--ocr-lang` ile seçin; daha yavaş fakat sınırlı
preprocessing planını `--ocr-exhaustive` ile açın. OCR heuristic bir analizdir;
stilize, hasarlı veya düşük kontrastlı metin çözülemeyebilir. Plan en fazla 20
kaynak görsel, görsel başına 20 variant ve 30 invocation, toplamda **200 OCR
invocation** çalıştırır. Her invocation **15 saniye** ve 1 MiB metinle, toplam
OCR metni 8 MiB ile sınırlıdır. Kaynak görsel sınırı 64 MiB ve 50 milyon decoded
pikseldir. Büyük exhaustive girdiler için `--timeout 60` gibi 60 saniye veya
daha uzun plugin timeout gerekebilir.

Pasif `qr_scanner`, hazır olduğunda OpenCV, pyzbar ve zbarimg backend'lerini
kullanır. QR'dan çözülen URL, komut, arşiv ve gömülü veriler mevcut sınırlar
içinde raporlanır veya incelenir; asla açılmaz, fetch edilmez veya çalıştırılmaz.
Kayıtlı pipeline **22 kayıtlı plugin** ve bunların **12 concurrent plugin**
işlemini korur.

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

Yapılandırma her alan için ayrı seçilir: açık CLI değeri boş olmayan ortam
değişkeninden, ortam değeri de varsayılan veya devre dışı durumdan önceliklidir.

| Amaç | CLI seçeneği | Ortam değişkeni |
|---|---|---|
| CTFd temel URL | `--ctfd-url` | `DAYI_CTFD_URL` |
| CTFd API token | `--ctfd-token` | `DAYI_CTFD_TOKEN` |
| CTFd challenge ID | `--challenge-id` | `DAYI_CTFD_CHALLENGE_ID` |
| Discord webhook | `--webhook` | `DAYI_DISCORD_WEBHOOK_URL` |
| Bildirim challenge adı | `--challenge-name` | `DAYI_CHALLENGE_NAME` |
| Optional writeup checkout | `--ctfshit-path` | `DAYI_CTFSHIT_PATH` |

Secret değerler için ortam değişkenlerini tercih edin. Gerçek token ve webhook
URL'lerini process listesi, shell history, terminal logu, ekran görüntüsü veya
commit edilmiş dosyalara koymayın. Yukarıdaki İngilizce örneklerdeki
`https://ctfd.example`, `https://discord.example/webhook` ve `TOKEN_REDACTED`
değerleri yalnızca güvenli placeholder'dır.

Manager oluşturulurken kullanılabilir aiohttp seçilir, yoksa stdlib urllib
kullanılır; transport seçimi tarama boyunca sabittir. CTFd ve Discord bağımsız
gönderilir ve entegrasyon hatası tamamlanmış taramayı geçersiz kılmaz.
`csl-ctfshitcli` yalnız zengin Markdown writeup için kullanılır; Discord ve CTFd
ona bağlı değildir ve yerleşik Markdown fallback olarak kalır.

Discord webhook URL'leri HTTPS gerektirir. CTFd HTTP geriye uyumluluk için kabul
edilir, fakat HTTPS önerilir. URL userinfo, query string ve fragment alanları
reddedilir; redirect engellenir, istek timeout'ları ve CTFd cevap okumaları
sınırlıdır. `dayi doctor` yalnızca yerel yapılandırmayı doğrular; endpoint,
credential veya erişilebilirlik testi yapmaz. Bildirim secret'ları TXT, JSON
veya Markdown raporlarına eklenmez.

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

### Yerel özel regresyon

Özel corpus, manifest ve raporlar bu repository'nin dışında kalmalıdır.
Challenge örneklerini veya tam flag değerlerini commit etmeyin; public
raporlarda dosya adı, yol, payload ve flag değerlerini redact edin. Gerçek özel
regresyonlar read-only ve yerel kalır; repository'ye yalnız deterministik
sentetik fixture ve testler eklenir.

Yerel harness ağ erişimini kapatır ve sınırları korur. İngilizce bölümdeki
`DAYI_PRIVATE_CORPUS`, `--timeout 180 --max-files 500`, `--anonymize`,
`--redact-flags` ve yerel kullanım için `--show-flags` seçenekleri geçerlidir.
Harness timeout, parser hatası, unsupported girdi ve eksik araçları ayrı
sınıflandırır. Çıkış durumu çözülen challenge sayısını değil harness veya
yapılandırma hatasını bildirir. Decoded payload çalıştırılmaz. Düzeltmeler
sentetik testlerle doğrulanmalı; özel challenge verisi fixture olmamalıdır.

---

## Lisans

Proje [MIT License](LICENSE) altında yayımlanır.

---

<div align="center">

Developed by [MacallanTheRoot](https://github.com/MacallanTheRoot)

**Dayı finds the evidence. You solve the challenge.**

</div>
