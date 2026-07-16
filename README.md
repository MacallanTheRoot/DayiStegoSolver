<div align="center">

# 🕵️ Dayı Stego Solver

### *"Hallederiz yeğenim." — The Uncle who always finds the flag.*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.0.0-success)](https://github.com/MacallanTheRoot/dayi-stego-solver)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Core%20Deps-Zero%20%28stdlib%29-brightgreen)](pyproject.toml)
[![Async](https://img.shields.io/badge/asyncio-gather-blue)](dayi/runner.py)

**English** | [Türkçe](#-türkçe-dokümantasyon)

> Developed with ☕ and CTF tears by [MacallanTheRoot](https://github.com/MacallanTheRoot)

> *"Dayı"* means Uncle in Turkish — the kind who knows how everything works, fixes things without asking twice, and never panics under pressure. Give him a stego challenge. He'll sort it.

</div>

---

## 🌐 English Documentation

### What is Dayı?

Throw a suspicious image at Dayı and walk away. It runs 9 plugin operations in parallel, grabs every string of text from the output, matches your flag regex, and — if you configured it — pings CTFd and Discord before you've opened a second terminal.

It logs at you like a wise, sarcastic Turkish uncle. The code itself is clean and boring, as it should be.

---

### 🆕 Latest upgrades

| Upgrade | Current behavior |
|---|---|
| **Multi-stage artifact scanner** | Passively reports HTTP/HTTPS URLs, validated IP addresses, conservative domains, credential hints, decimal/DMS coordinates, and printable Base64 hints. It never fetches, resolves, or follows an artifact. |
| **Intelligent mini-wordlist decoder** | Quietly adds printable Hex and strict Base64 decodings alongside their original tokens, with deterministic deduplication and bounded candidate limits. |
| **ZIP carving and cracking** | `binwalk` explicitly carves raw ZIP bytes even when external extraction fails. Extensionless ZIPs are detected by content, then safely extracted or tried with the mini-wordlist before the streamed main wordlist. |
| **Pure-Python chi-square analysis** | Reconstructs bounded PNG scanlines and uncompressed BMP pixels without Pillow/NumPy/SciPy, then reports an LSB Pair-of-Values uniformity heuristic. |
| **Dynamic plugin registry** | Discovers validated `PLUGIN_SPECS` automatically, orders them by phase and priority, and skips malformed plugins without crashing the scan. |
| **Optional Rich terminal UI** | Provides one coordinated live display, plugin status, progress, artifact panels, and flag tables when Rich and an interactive TTY are available. |
| **Optional OCR plugin** | After archive handling, scans the target and extracted JPEG/PNG/BMP images for visible text and flags. Pillow, pytesseract, and the system Tesseract engine remain optional. |

Security hardening also rejects noisy short-domain/IPv6 artifacts, ZIP path traversal, symlink escapes, oversized archive members, decompression bombs, oversized OCR inputs, and duplicate workspace images.

---

### ✨ Features

| | Feature | What it actually does |
|---|---|---|
| ⚡ | **Concurrent execution** | `asyncio.gather()` fires all 9 concurrent plugin operations at once. ~75% faster than the old sequential loop. |
| 🔌 | **Drop-in plugins** | Public modules under `dayi/tools/` self-register with `PLUGIN_SPECS`; the runner needs no edits. |
| 🎨 | **Optional Rich UI** | `.[ui]` adds one coordinated live display, progress bars, warning panels, and flag tables; non-TTY and zero-dependency installs stay plain. |
| 👁️ | **Optional OCR** | `.[ocr]` reads visible text from the target and images unpacked into the workspace; the core remains dependency-free. |
| 🧭 | **Passive artifact detection** | Reports links, IPs, domains, credential hints, coordinates, and validated Base64 previews without network access. |
| 🔐 | **Safe archive recovery** | Carves extensionless ZIPs, tries contextual passwords first, and enforces traversal and extraction-size limits. |
| 🔓 | **Intelligent token decoding** | Adds printable Hex and strict Base64 decodings to the bounded contextual password pool. |
| 📊 | **Chi-square LSB test** | Measures PNG/BMP Pair-of-Values distributions with a pure-stdlib p-value heuristic. |
| 🧠 | **Smart routing** | Reads the first 16 bytes. JPEG → no zsteg. PNG → no steghide. No wasted forks. |
| 🔔 | **Early notification** | Flag found by exiftool while binwalk is still running? CTFd gets it immediately. |
| 🔍 | **Mini-wordlist BF** | Pulls candidate passwords from metadata output and tries them before touching rockyou. |
| 📝 | **Auto write-up** | Generates a Markdown writeup. Uses ctfshit's exporter if available, falls back to its own. |
| 🧹 | **Zombie-safe subprocess** | SIGTERM → 2s grace → SIGKILL → `wait_for(5s)`. Stuck processes don't linger. |
| 🔒 | **OOM-safe wordlists** | rockyou.txt is streamed line-by-line. 134MB never hits RAM as a whole. |
| 🛡️ | **Token sanitization** | Strips null bytes and control chars before handing tokens to steghide subprocess args. |
| 🧩 | **ctfshit integration** | Drop ctfshit in the project root. Dayı finds it automatically. No config needed. |
| 🔄 | **3-tier HTTP fallback** | ctfshit → aiohttp → stdlib urllib. Notifications go out regardless of what's installed. |
| 🗂️ | **Flag attribution** | Report says `CTF{flag} ← found by: exiftool, binwalk`. Useful. |
| ⌨️ | **Ctrl+C safe** | Hit interrupt anytime. Partial results are written. Nothing is lost. |

---

### 🗂️ Format → Tool Matrix

| Format | Magic bytes | exiftool | exiv2 | strings | binwalk | zsteg | lsb_py | chi_square | steghide | outguess | stegseek | ocr |
|:------:|:-----------:|:--------:|:-----:|:-------:|:-------:|:-----:|:------:|:----------:|:--------:|:--------:|:--------:|:---:|
| **JPEG** | `FF D8 FF` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **PNG** | `89 50 4E 47` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| **BMP** | `42 4D` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **WAV** | `52 49 46 46` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **ZIP** | `50 4B 03 04` | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Unknown** | — | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

> Routing is header-based. Rename a JPEG to `.png` — Dayı still knows what it is.

#### Tool reference

| Tool | Type | What it does | Install |
|------|------|-------------|---------|
| `exiftool` | External | EXIF/metadata dump | `sudo apt install libimage-exiftool-perl` |
| `exiv2` | External | EXIF/IPTC/XMP metadata | `sudo apt install exiv2` |
| `strings` | External | Printable string extraction | `sudo apt install binutils` |
| `binwalk` | External | Embedded extraction + raw ZIP carving fallback | `sudo apt install binwalk` |
| `zip_cracker` | **Built-in** | Safe extensionless/ZipCrypto recovery and recursive flag scan | nothing |
| `zsteg` | External | PNG/BMP LSB analysis | `sudo gem install zsteg` |
| `lsb_py` | **Built-in** | PNG/BMP LSB (pure Python, no Ruby needed) | nothing |
| `chi_square` | **Built-in** | PNG/BMP PoV chi-square LSB heuristic | nothing |
| `ocr_scanner` | Optional plugin | OCR on the target and extracted JPEG/PNG/BMP images | `pip install -e ".[ocr]"` + Tesseract |
| `steghide` | External | JPEG/BMP/WAV steghide | `sudo apt install steghide` |
| `outguess` | External | JPEG outguess | `sudo apt install outguess` |
| `stegseek` | External | Native-speed steghide BF | [github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek) |

---

### 📦 Installation

```bash
git clone https://github.com/MacallanTheRoot/dayi-stego-solver.git
cd dayi-stego-solver

python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Rich spinner, progress bars, panels, and result tables (optional)
pip install -e ".[ui]"

# Visible-text OCR for target and extracted images (optional)
pip install -e ".[ocr]"

# Tier-2 Discord/CTFd fallback (if you're not using ctfshit)
pip install -e ".[integration]"

dayi --help
```

**System tools (Kali/Debian/Ubuntu):**

```bash
sudo apt install -y libimage-exiftool-perl exiv2 binutils binwalk steghide outguess
sudo gem install zsteg

# Required only when the optional OCR extra is used
sudo apt install -y tesseract-ocr

# stegseek — worth it, trust me
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

**ctfshit integration (optional):**

```bash
# Clone it as a sibling directory — Dayı auto-detects it at runtime
git clone https://github.com/MacallanTheRoot/ctfshitcli ctfshit/
```

No config file. No env vars. If `ctfshit/src/*.py` is importable, it gets used.

---

### 🚀 Usage

```bash
# Basic
dayi photo.jpg --flag "CTF{.*?}"

# With rockyou (streamed, safe)
dayi stego.jpg --flag "picoCTF{.*?}" --wordlist /usr/share/wordlists/rockyou.txt

# JSON report, verbose
dayi mystery.png --flag "HTB{.*?}" -v --output report --format json
```

**Full pipeline — everything at once:**

```bash
dayi challenge.jpg \
    --flag "CTF{.*?}" \
    --wordlist rockyou.txt \
    --timeout 120 \
    --threads 16 \
    --bf-limit 50000 \
    --writeup writeup.md \
    --ctfd-url https://ctf.example.com \
    --ctfd-token YOUR_TOKEN \
    --challenge-id 42 \
    --webhook "https://discord.com/api/webhooks/…" \
    --output report \
    --format json \
    --log-file dayi.log \
    -v
```

**Argument order doesn't matter** — `parse_intermixed_args()` handles it:

```bash
dayi --flag "CTF{.*?}" --output rapor image.png   # file last — fine
dayi --flag "FLAG{.*?}" mystery.bmp --wordlist words.txt  # file in the middle — also fine
```

**All flags:**

```
Core:
  DOSYA                   Target file
  --flag/-f REGEX         Flag pattern. E.g. "CTF{.*?}"
  --wordlist/-w FILE      BF wordlist
  --output/-o PATH        Report name (no extension). Default: dayi_rapor
  --format {txt,json}     Default: txt
  --timeout/-t N          Per-tool timeout in seconds. Default: 60
  --threads N             BF worker count. Default: 8
  --bf-limit N            Max BF attempts (0=unlimited). Default: 1000
  --log-file FILE         Also write logs here
  -v/--verbose            Debug output

Integration (v2.0):
  --webhook URL           Discord webhook
  --ctfd-url URL          CTFd base URL
  --ctfd-token TOKEN      CTFd API token
  --challenge-id ID       Challenge ID for auto-submit
  --challenge-name NAME   Challenge name in Discord embed

Write-up (v3.0):
  --writeup FILE.md       Generate Markdown writeup after scan
```

---

### ⚙️ How it runs

```
┌──────────────────────────────────────────────────┐
│  Phases 1–4  (asyncio.gather — all at once)      │
│                                                  │
│  exiftool  exiv2  strings  binwalk               │
│  zsteg     lsb_py  chi_square                     │
│  steghide  outguess                               │
│                                                  │
│  → flag found mid-gather? notify() fires now.    │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 4.5 — Archive post-processing             │
│  ZIP: mini-list → streamed main list → safe scan │
│  OCR: target + extracted images (when installed) │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 4.6 — Mini-wordlist BF                    │
│  Pulls tokens from phases 1+2 output             │
│  → Tries them against steghide + outguess        │
│  → If it works, skips Phase 5 entirely           │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 5 — Main wordlist BF                      │
│  stegseek first (C++, fast)                      │
│  → if stegseek fails: steghide_bf, outguess_bf   │
└──────────────────────────────────────────────────┘
                       ↓
              TXT / JSON / Markdown
```

---

### 🔗 Integration

**How notifications work:**

```
flag found
  │
  ▼
notify(flag, tool)   ← asyncio.create_task, returns immediately
  │
  ├─ ctfshit installed?  → FlagSubmitter + send_flag_notification
  ├─ aiohttp installed?  → direct POST to CTFd + Discord webhook
  └─ neither?            → urllib (run_in_executor, non-blocking)
```

Won't crash if ctfshit is missing. Won't crash if the webhook is dead. Same flag never goes out twice — tracked in a `set()`.

**Write-up export:**

```python
# ctfshit present: creates a temp workspace, drops .challenge.json + notes.txt,
# calls export_writeups(), cleans up.
export_markdown_writeup(report, Path("writeup.md"))

# ctfshit absent: built-in fallback, same output path, zero deps.
```

---

### 🏗️ Project layout

```
DayiStegoSolver/
├── dayi/
│   ├── cli.py              # argparse entry point
│   ├── runner.py           # generic phase-aware plugin orchestrator
│   ├── scanner.py          # regex flag scanner
│   ├── reporter.py         # TXT + JSON + Markdown writeup
│   ├── persona.py          # Dayı voice, colors, banners
│   ├── integrations.py     # CTFd/Discord fire-and-forget
│   └── tools/
│       ├── _base.py        # subprocess wrapper, SIGTERM/SIGKILL, sanitizer
│       ├── _plugin.py      # plugin contract, validation, dynamic discovery
│       ├── lsb.py          # pure-Python PNG/BMP LSB (no zsteg dependency)
│       ├── chi_square.py   # bounded PNG/BMP PoV statistical analyzer
│       ├── ocr_scanner.py  # optional OCR for target and workspace images
│       ├── zip_cracker.py  # safe stdlib ZipCrypto cracking
│       ├── steghide.py     # empty-pass + streaming BF
│       ├── outguess.py     # empty-pass + streaming BF
│       ├── binwalk.py      # extraction + protected-ZIP carving fallback
│       └── …               # exiftool, exiv2, strings, zsteg, stegseek
├── ctfshit/                # optional — drop here, auto-detected
├── pyproject.toml
└── .gitignore
```

---

### 🧪 Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v

# No pytest? Quick sanity:
python -c "from dayi.cli import build_arg_parser; print('OK')"
dayi --help
```

---

### 🤝 Contributing

PRs welcome. A few rules:

1. New tool? Copy `dayi/tools/exiftool.py` as a template.
2. Export a non-empty `PLUGIN_SPECS` tuple containing validated `ToolPlugin` operations. The registry discovers public modules automatically; `runner.py` changes are not needed.
3. Choose the correct `PluginPhase`, priority, requirements, and skip dependencies. Add a format guard with `get_file_type()` + `make_skipped_result()` where applicable.
4. Treat drop-in plugins as trusted local code: discovery imports each public module. Malformed plugins are skipped with a warning.
5. Code/comments/docstrings → English. `logger.info()` messages → Turkish, Dayı tone.

---

### 📄 License

MIT — do whatever you want with it.

---

---

## 🇹🇷 Türkçe Dokümantasyon

<div align="center">

### *"Hallederiz yeğenim." — CTF Steganografisinin Bilge Dayısı*

> [MacallanTheRoot](https://github.com/MacallanTheRoot) tarafından ☕ ve CTF gözyaşlarıyla geliştirildi.

</div>

---

### Dayı Nedir?

Şüpheli görseli Dayı'ya ver, geri adım at. 9 aracı aynı anda çalıştırır, çıktıları regex'le tarar, flag bulursa — eğer yapılandırdıysan — ikinci terminali açmadan CTFd'ye ve Discord'a haber uçurur.

Seninle bilge, nükteli bir Türk dayısı ağzıyla konuşur. Kodun kendisi sıkıcı derecede temiz.

---

### 🆕 Son yükseltmeler

| Yükseltme | Güncel davranış |
|---|---|
| **Çok aşamalı artifact tarayıcı** | HTTP/HTTPS bağlantılarını, doğrulanmış IP adreslerini, temkinli domain eşleşmelerini, kimlik bilgisi ipuçlarını, decimal/DMS koordinatlarını ve yazdırılabilir Base64 ipuçlarını pasif biçimde raporlar. Hiçbir bağlantıyı çekmez, çözümlemez veya takip etmez. |
| **Akıllı mini-wordlist decoder** | Yazdırılabilir Hex ve katı Base64 çözümlerini özgün token'larla birlikte sessizce ekler; adayları deterministik biçimde tekilleştirir ve sınırlar. |
| **ZIP carving ve şifre çözme** | Harici çıkarma başarısız olsa bile `binwalk` ham ZIP baytlarını ayrıca carve eder. Uzantısız ZIP'ler içerikten tanınır; önce mini-wordlist, sonra stream edilen ana wordlist denenir. |
| **Saf Python chi-square analizi** | Pillow/NumPy/SciPy olmadan sınırlandırılmış PNG scanline'larını ve sıkıştırılmamış BMP piksellerini çözer; LSB Pair-of-Values uniformity heuristic'ini raporlar. |
| **Dinamik eklenti registry'si** | `PLUGIN_SPECS` tanımlarını otomatik keşfeder, faz ve önceliğe göre sıralar; bozuk eklentileri taramayı çökertmeden atlar. |
| **İsteğe bağlı Rich terminal UI** | Rich ve interaktif TTY varsa tek bir canlı ekran üzerinden eklenti durumu, ilerleme, artifact panelleri ve flag tabloları gösterir. |
| **İsteğe bağlı OCR eklentisi** | Arşiv işlemlerinden sonra hedefi ve çıkarılan JPEG/PNG/BMP görsellerini görünür yazı ve flag için tarar. Pillow, pytesseract ve sistem Tesseract motoru isteğe bağlı kalır. |

Güvenlik sıkılaştırmaları; kısa domain/IPv6 gürültüsünü, ZIP path traversal girişimlerini, symlink kaçışlarını, aşırı büyük arşiv üyelerini, decompression bomb'larını, büyük OCR girdilerini ve yinelenen çalışma alanı görsellerini de engeller.

---

### ✨ Özellikler

| | Özellik | Ne yapar |
|---|---|---|
| ⚡ | **Eşzamanlı çalışma** | `asyncio.gather()` ile 9 araç aynı anda. Eski sıralı yapıya göre ~%75 hız kazancı. |
| 🔌 | **Drop-in eklentiler** | `dayi/tools/` altındaki açık modüller `PLUGIN_SPECS` ile kendini kaydeder; runner değişmez. |
| 🎨 | **İsteğe bağlı Rich UI** | `.[ui]` tek bir canlı ekran, ilerleme çubukları, uyarı panelleri ve flag tabloları ekler; TTY dışı ve sıfır-bağımlılık kurulumu düz kalır. |
| 👁️ | **İsteğe bağlı OCR** | `.[ocr]` hedefteki ve çalışma alanına çıkarılmış görsellerdeki görünür yazıları okur; çekirdek bağımlılıksız kalır. |
| 🧭 | **Pasif artifact tespiti** | Bağlantı, IP, domain, kimlik bilgisi ipucu, koordinat ve doğrulanmış Base64 önizlemelerini ağa çıkmadan raporlar. |
| 🔐 | **Güvenli arşiv kurtarma** | Uzantısız ZIP'leri carve eder, önce bağlamsal şifreleri dener; traversal ve çıkarma boyutu sınırlarını uygular. |
| 🔓 | **Akıllı token çözme** | Yazdırılabilir Hex ve katı Base64 çözümlerini sınırlandırılmış bağlamsal şifre havuzuna ekler. |
| 🧠 | **Akıllı yönlendirme** | İlk 16 byte'ı okur. JPEG → zsteg yok. PNG → steghide yok. Boşuna fork yok. |
| 🔔 | **Erken bildirim** | exiftool flag buldu, binwalk hâlâ çalışıyor? CTFd anında haberdar olur. |
| 🔍 | **Mini-wordlist BF** | Metadata çıktısından aday şifreler toplar, rockyou'ya girmeden önce dener. |
| 📊 | **Chi-square LSB testi** | PNG/BMP renk kanallarında PoV dağılımını ölçer; p-value tabanlı skor bir heuristic'tir, kesin stego kanıtı değildir. |
| 📝 | **Otomatik write-up** | Markdown çözüm belgesi üretir. ctfshit varsa onun exporter'ını kullanır, yoksa kendisi yapar. |
| 🧹 | **Zombie-safe subprocess** | SIGTERM → 2s → SIGKILL → `wait_for(5s)`. Takılı process bırakmaz. |
| 🔒 | **OOM koruması** | rockyou.txt satır satır stream edilir. 134MB RAM'e hiç yüklenmez. |
| 🛡️ | **Token temizleme** | Null-byte ve kontrol karakterlerini steghide argümanlarına gitmeden önce siler. |
| 🧩 | **ctfshit entegrasyonu** | ctfshit'i proje dizinine klonla, Dayı otomatik bulur. Ayar gerekmez. |
| 🔄 | **3 katmanlı HTTP fallback** | ctfshit → aiohttp → stdlib urllib. Ne yüklü olursa, bildirim gider. |
| 🗂️ | **Flag attribution** | Raporda `CTF{flag} ← bulan: exiftool, binwalk` yazar. |
| ⌨️ | **Ctrl+C güvenli** | İstediğin zaman dur. Kısmi sonuçlar yazılır. Veri kaybolmaz. |

---

### 📦 Kurulum

```bash
git clone https://github.com/MacallanTheRoot/dayi-stego-solver.git
cd dayi-stego-solver

python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Rich spinner, progress bar, panel ve sonuç tabloları (isteğe bağlı)
pip install -e ".[ui]"

# Hedef ve çıkarılmış görsellerde görünür yazı OCR'ı (isteğe bağlı)
pip install -e ".[ocr]"

# CTFd/Discord fallback için (ctfshit olmadan)
pip install -e ".[integration]"
```

**Sistem araçları (Kali / Debian / Ubuntu):**

```bash
sudo apt install -y libimage-exiftool-perl exiv2 binutils binwalk steghide outguess
sudo gem install zsteg

# Yalnızca isteğe bağlı OCR extra'sı kullanılırken gerekir
sudo apt install -y tesseract-ocr
# stegseek: https://github.com/RickdeJager/stegseek/releases
```

**ctfshit (isteğe bağlı):**

```bash
git clone https://github.com/MacallanTheRoot/ctfshitcli ctfshit/
# Ayar yok. Dizinde varsa Dayı kullanır.
```

---

### 🚀 Kullanım

```bash
# Temel
dayi foto.jpg --flag "CTF{.*?}"

# Wordlist ile (stream edilir, OOM yok)
dayi stego.jpg --flag "picoCTF{.*?}" --wordlist /usr/share/wordlists/rockyou.txt

# JSON rapor, detaylı
dayi mystery.png --flag "HTB{.*?}" -v --output rapor --format json
```

**Tam pipeline:**

```bash
dayi challenge.jpg \
    --flag "CTF{.*?}" \
    --wordlist rockyou.txt \
    --timeout 120 \
    --threads 16 \
    --bf-limit 50000 \
    --writeup cozum.md \
    --ctfd-url https://ctf.example.com \
    --ctfd-token TOKEN \
    --challenge-id 42 \
    --webhook "https://discord.com/api/webhooks/…" \
    --output rapor \
    --format json \
    -v
```

---

### ⚙️ Çalışma sırası

```
Faz 1–4 (asyncio.gather — hepsi aynı anda):
  exiftool  exiv2  strings  binwalk
  zsteg     lsb_py  chi_square
  steghide_empty    outguess_empty
  → Flag bulunur bulunmaz notify() tetiklenir.

Faz 4.5 — Arşiv son işlemleri:
  ZIP: mini-wordlist → stream edilen ana wordlist → güvenli tarama
  OCR: hedef + çıkarılmış görseller (kuruluysa)

Faz 4.6 — Mini-wordlist BF:
  Metadata çıktısından token topla → steghide/outguess'e ver
  → Şifre bulunursa Faz 5 atlanır.

Faz 5 — Ana wordlist BF:
  stegseek (C++, hızlı) → başarısız olursa → steghide_bf, outguess_bf

Son: TXT / JSON rapor + --writeup verilmişse Markdown
```

---

### 🔗 Entegrasyon — CTFd & Discord

```bash
# Sadece Discord
dayi foto.jpg --flag "CTF{.*?}" --webhook "https://discord.com/api/webhooks/…"

# Sadece CTFd
dayi foto.jpg --flag "CTF{.*?}" \
    --ctfd-url https://ctf.example.com --ctfd-token TOKEN --challenge-id 42
```

Kütüphane önceliği: ctfshit → aiohttp → urllib. Aynı flag iki kez gönderilmez (`set()` koruması). Webhook çökerse program çökmez.

---

### 📝 Otomatik write-up

```bash
dayi stego.png --flag "CTF{.*?}" --writeup cozum.md
# ctfshit varsa: kategori gruplu, timestamp'li zengin Markdown
# ctfshit yoksa: yerleşik fallback, sıfır bağımlılık — yine de dosya üretilir
```

---

### 🤝 Katkı

PR'lar bekliyorum. Kurallar basit:

1. Yeni araç → `dayi/tools/exiftool.py`'yi template al.
2. Doğrulanabilir `ToolPlugin` işlemlerinden oluşan boş olmayan bir `PLUGIN_SPECS` tuple'ı dışa aktar. Registry modülü otomatik keşfeder; `runner.py` değişmez.
3. Doğru `PluginPhase`, öncelik, gereksinim ve atlama bağımlılıklarını seç. Uygun araçlarda `get_file_type()` ile format kontrolü ekle.
4. Drop-in eklentileri güvenilir yerel kod kabul et: keşif sırasında modüller import edilir. Bozuk eklenti uyarıyla atlanır.
5. Kod/yorum → İngilizce. `logger.info()` mesajları → Türkçe, Dayı tonu.

---

### 📄 Lisans

MIT — istediğin gibi kullan.

---

<div align="center">

*"Nasıl mı yaptım? Dayı halleder yeğenim, sormaya gerek yok."*

**⭐ Beğendiysen yıldızla. Dayı mutlu olur.**

</div>
