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

Throw a suspicious image at Dayı and walk away. It runs 8 tools in parallel, grabs every string of text from the output, matches your flag regex, and — if you configured it — pings CTFd and Discord before you've opened a second terminal.

It logs at you like a wise, sarcastic Turkish uncle. The code itself is clean and boring, as it should be.

---

### ✨ Features

| | Feature | What it actually does |
|---|---|---|
| ⚡ | **Concurrent execution** | `asyncio.gather()` fires all 8 tools at once. ~75% faster than the old sequential loop. |
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

| Format | Magic bytes | exiftool | exiv2 | strings | binwalk | zsteg | lsb_py | steghide | outguess | stegseek |
|:------:|:-----------:|:--------:|:-----:|:-------:|:-------:|:-----:|:------:|:--------:|:--------:|:--------:|
| **JPEG** | `FF D8 FF` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **PNG** | `89 50 4E 47` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **BMP** | `42 4D` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **WAV** | `52 49 46 46` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **ZIP** | `50 4B 03 04` | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Unknown** | — | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

> Routing is header-based. Rename a JPEG to `.png` — Dayı still knows what it is.

#### Tool reference

| Tool | Type | What it does | Install |
|------|------|-------------|---------|
| `exiftool` | External | EXIF/metadata dump | `sudo apt install libimage-exiftool-perl` |
| `exiv2` | External | EXIF/IPTC/XMP metadata | `sudo apt install exiv2` |
| `strings` | External | Printable string extraction | `sudo apt install binutils` |
| `binwalk` | External | Embedded file extraction | `sudo apt install binwalk` |
| `zsteg` | External | PNG/BMP LSB analysis | `sudo gem install zsteg` |
| `lsb_py` | **Built-in** | PNG/BMP LSB (pure Python, no Ruby needed) | nothing |
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

# Tier-2 Discord/CTFd fallback (if you're not using ctfshit)
pip install -e ".[integration]"

dayi --help
```

**System tools (Kali/Debian/Ubuntu):**

```bash
sudo apt install -y libimage-exiftool-perl exiv2 binutils binwalk steghide outguess
sudo gem install zsteg

# stegseek — worth it, trust me
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_linux.deb
sudo dpkg -i stegseek_linux.deb
```

**ctfshit integration (optional):**

```bash
# Clone it as a sibling directory — Dayı auto-detects it at runtime
git clone https://github.com/MacallanTheRoot/ctfshit ctfshit/
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
│  zsteg     lsb_py  steghide  outguess            │
│                                                  │
│  → flag found mid-gather? notify() fires now.    │
└──────────────────────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────┐
│  Phase 4.5 — Mini-wordlist BF                    │
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
│   ├── runner.py           # asyncio.gather orchestrator, 5 phases
│   ├── scanner.py          # regex flag scanner
│   ├── reporter.py         # TXT + JSON + Markdown writeup
│   ├── persona.py          # Dayı voice, colors, banners
│   ├── integrations.py     # CTFd/Discord fire-and-forget
│   └── tools/
│       ├── _base.py        # subprocess wrapper, SIGTERM/SIGKILL, sanitizer
│       ├── lsb.py          # pure-Python PNG/BMP LSB (no zsteg dependency)
│       ├── steghide.py     # empty-pass + streaming BF
│       ├── outguess.py     # empty-pass + streaming BF
│       ├── binwalk.py      # extraction + recursive dir scan
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
2. Add a format guard with `get_file_type()` + `make_skipped_result()` — no guard, no merge.
3. Add it to `tools/__init__.py` and `runner.py`'s `concurrent_coros` list.
4. Code/comments/docstrings → English. `logger.info()` messages → Turkish, Dayı tone.

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

Şüpheli görseli Dayı'ya ver, geri adım at. 8 aracı aynı anda çalıştırır, çıktıları regex'le tarar, flag bulursa — eğer yapılandırdıysan — ikinci terminali açmadan CTFd'ye ve Discord'a haber uçurur.

Seninle bilge, nükteli bir Türk dayısı ağzıyla konuşur. Kodun kendisi sıkıcı derecede temiz.

---

### ✨ Özellikler

| | Özellik | Ne yapar |
|---|---|---|
| ⚡ | **Eşzamanlı çalışma** | `asyncio.gather()` ile 8 araç aynı anda. Eski sıralı yapıya göre ~%75 hız kazancı. |
| 🧠 | **Akıllı yönlendirme** | İlk 16 byte'ı okur. JPEG → zsteg yok. PNG → steghide yok. Boşuna fork yok. |
| 🔔 | **Erken bildirim** | exiftool flag buldu, binwalk hâlâ çalışıyor? CTFd anında haberdar olur. |
| 🔍 | **Mini-wordlist BF** | Metadata çıktısından aday şifreler toplar, rockyou'ya girmeden önce dener. |
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

# CTFd/Discord fallback için (ctfshit olmadan)
pip install -e ".[integration]"
```

**Sistem araçları (Kali / Debian / Ubuntu):**

```bash
sudo apt install -y libimage-exiftool-perl exiv2 binutils binwalk steghide outguess
sudo gem install zsteg
# stegseek: https://github.com/RickdeJager/stegseek/releases
```

**ctfshit (isteğe bağlı):**

```bash
git clone https://github.com/MacallanTheRoot/ctfshit ctfshit/
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
  zsteg     lsb_py  steghide  outguess
  → Flag bulunur bulunmaz notify() tetiklenir.

Faz 4.5 — Mini-wordlist BF:
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
2. `get_file_type()` ile format kontrolü ekle. Yoksa merge yok.
3. `tools/__init__.py` ve `runner.py`'deki `concurrent_coros` listesine ekle.
4. Kod/yorum → İngilizce. `logger.info()` mesajları → Türkçe, Dayı tonu.

---

### 📄 Lisans

MIT — istediğin gibi kullan.

---

<div align="center">

*"Nasıl mı yaptım? Dayı halleder yeğenim, sormaya gerek yok."*

**⭐ Beğendiysen yıldızla. Dayı mutlu olur.**

</div>
