"""
dayi/persona.py
~~~~~~~~~~~~~~~
Dayı's voice: log colors, flavor text, banners.

Turkish for the user. English for the code. That's the deal.
"""
import logging
import sys
from typing import Optional


# ANSI codes — nothing fancy, just what works in every terminal
class _Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"


# Custom level: sits between INFO and WARNING so flag hits stand out
FOUND_LEVEL = 25
logging.addLevelName(FOUND_LEVEL, "FOUND")


# ---------------------------------------------------------------------------
# Per-tool Dayı flavor text
# ---------------------------------------------------------------------------

TOOL_INTROS: dict[str, str] = {
    "exiftool":    "[+] Ver o dosyayı bana yeğenim, ben hallederim... Exiftool ile röntgeni çekiliyor...",
    "binwalk":     "[+] Dosyanın karnı şişmiş gibi duruyor. Binwalk ile içini yokluyorum...",
    "strings":     "[+] Strings ile dosyanın sırlarını konuşturmaya çalışıyorum, sabreyle...",
    "zsteg":       "[+] PNG/BMP'ye bakalım dedim. Zsteg çantadan çıkıyor...",
    "steghide":    "[+] Şifreli kapı mı? Korkmam, steghide ile çalıyorum...",
    "stegseek":    "[+] Stegseek ile wordlist'i salıyorum, ta-da-da-da-da...",
    "outguess":    "[+] Outguess devreye girdi, bu iş hallolmadan gitmez...",
    "exiv2":       "[+] EXIF metadata'sının altına bakıyorum, exiv2 ile şüpheli meta avı...",
    "steghide_bf": "[+] Brute-force zamanı yeğenim! Steghide'a wordlist'i seriyorum...",
    "outguess_bf": "[+] Outguess'e de wordlist veriyorum, bu kadar inat olmaz...",
}

TOOL_SKIP_MESSAGES: dict[str, str] = {
    "exiftool":    "[-] Yeğenim sistemde exiftool yok, onu bir kur da gel. Geçiyorum...",
    "binwalk":     "[-] Binwalk kurulu değil. 'sudo apt install binwalk' desen iyi olur. Devam...",
    "strings":     "[-] Strings bulunamadı?! Bu sistemde neler oluyor? Atlıyorum...",
    "zsteg":       "[-] Yeğenim sistemde zsteg yok, 'gem install zsteg' yap da gel. Geçiyorum...",
    "steghide":    "[-] Steghide kurulu değil. 'sudo apt install steghide' demeliydin. Atlıyorum...",
    "stegseek":    "[-] Stegseek bulunamadı. GitHub'dan derle veya indirip kur. Devam...",
    "outguess":    "[-] Outguess yok mu sistemde? 'sudo apt install outguess' ile çözersin. Geçiyorum...",
    "exiv2":       "[-] Exiv2 kurulmamış. 'sudo apt install exiv2' ile halledersin. Atlıyorum...",
    "steghide_bf": "[-] Steghide brute-force atlandı (tool yok). Devam...",
    "outguess_bf": "[-] Outguess brute-force atlandı (tool yok). Devam...",
}

TOOL_TIMEOUT_MESSAGES: dict[str, str] = {
    "default": "[-] Bu araç çok oyalandı yeğenim, timeout! Sıradakine geçiyorum...",
}

TOOL_SUCCESS_MESSAGES: dict[str, str] = {
    "default": "[✓] Bitti. Çıktıyı inceliyorum...",
}

TOOL_ERROR_MESSAGES: dict[str, str] = {
    "default": "[!] Bir şeyler ters gitti ama ben yılmam yeğenim. Devam ediyorum...",
}

FLAG_FOUND_BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  🎯  FLAG BULUNDU! İşte bu yeğenim, tam gaz devam!  🎯      ║
╚══════════════════════════════════════════════════════════════╝
"""

NO_FLAG_BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  😤  Flag bulunamadı... Ama Dayı'nın raporu hazır.          ║
║  Manuel incelemeye geçebilirsin yeğenim.                     ║
╚══════════════════════════════════════════════════════════════╝
"""

BANNER = r"""
    ____  ___   __  ______
   / __ \/ _ | \/ / /  _/
  / / / / /| | \  / / /
 / /_/ / ___ | / / / /
/_____/_/ _|_|/_/___/

  Dayı Stego Solver v3.0  —  "Hallederiz Yeğenim" Edition
  ════════════════════════════════════════════════════════
  Dev by MacallanTheRoot · https://github.com/MacallanTheRoot
"""


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class DayiFormatter(logging.Formatter):
    """Colors per level. No timestamps in console — keeps output clean."""

    LEVEL_COLOR_MAP: dict[int, str] = {
        logging.DEBUG:    _Colors.BLUE,
        logging.INFO:     _Colors.CYAN,
        FOUND_LEVEL:      _Colors.GREEN + _Colors.BOLD,
        logging.WARNING:  _Colors.YELLOW,
        logging.ERROR:    _Colors.RED,
        logging.CRITICAL: _Colors.RED + _Colors.BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLOR_MAP.get(record.levelno, _Colors.WHITE)
        return f"{color}{super().format(record)}{_Colors.RESET}"


def setup_logger(
    name: str = "dayi",
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """
    Build the application logger.

    Console: colored, no timestamps.
    File (if given): plain text with timestamps, DEBUG-level.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(DayiFormatter("%(message)s"))
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)

    return logger


def log_found(logger: logging.Logger, message: str) -> None:
    """Emit at FOUND level (25) — between INFO and WARNING, always visible."""
    logger.log(FOUND_LEVEL, message)
