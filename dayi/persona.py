"""
dayi/persona.py
~~~~~~~~~~~~~~~
Dayı's voice: log colors, flavor text, banners.

Turkish for the user. English for the code. That's the deal.
"""
import logging
import sys
import threading
from dataclasses import dataclass
from typing import Any, Optional, TextIO


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


# Custom levels: sit between INFO and WARNING so discoveries stand out.
FOUND_LEVEL = 25
logging.addLevelName(FOUND_LEVEL, "FOUND")
ARTIFACT_LEVEL = 26
logging.addLevelName(ARTIFACT_LEVEL, "ARTIFACT")


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
        ARTIFACT_LEVEL:   _Colors.YELLOW + _Colors.BOLD,
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
    logger.propagate = False

    for handler in tuple(logger.handlers):
        if getattr(handler, "_dayi_owned", False):
            logger.removeHandler(handler)
            handler.close()

    console = logging.StreamHandler(sys.stdout)
    console._dayi_owned = True  # type: ignore[attr-defined]
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(DayiFormatter("%(message)s"))
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh._dayi_owned = True  # type: ignore[attr-defined]
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)

    return logger


def log_found(logger: logging.Logger, message: str) -> None:
    """Emit at FOUND level (25) — between INFO and WARNING, always visible."""
    logger.log(FOUND_LEVEL, message)


def log_artifact(logger: logging.Logger, message: str) -> None:
    """Emit a bold warning for a passive next-stage artifact discovery."""
    logger.log(ARTIFACT_LEVEL, message)


# ---------------------------------------------------------------------------
# Optional terminal UI
# ---------------------------------------------------------------------------


class TerminalUI:
    """Presentation contract used by the runner and plugin progress callbacks."""

    is_rich = False

    def phase_started(self, phase: str, plugins: tuple[str, ...]) -> None:
        """Announce an execution phase and its scheduled plugins."""

    def phase_finished(self, phase: str) -> None:
        """Mark an execution phase as finished."""

    def plugin_started(self, plugin_id: str) -> None:
        """Mark one plugin as running."""

    def plugin_progress(
        self,
        plugin_id: str,
        attempted: int,
        total: int | None,
    ) -> None:
        """Update password-attempt progress for one plugin."""

    def plugin_finished(self, plugin_id: str, outcome: str) -> None:
        """Mark one plugin as complete, skipped, timed out, or failed."""

    def show_artifact(self, message: str) -> None:
        """Present a passive artifact or high-confidence anomaly."""

    def show_flag(self, flag: str, source: str | None = None) -> None:
        """Present a discovered flag prominently."""

    def show_warning(self, message: str) -> None:
        """Present an operational warning."""

    def show_no_flags(self) -> None:
        """Present the no-flags-found summary."""

    def close(self) -> None:
        """Release terminal resources. Calls must be idempotent."""


class PlainTerminalUI(TerminalUI):
    """Standard-library UI preserving the existing logging experience."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("dayi")
        self._flag_banner_shown = False

    def phase_started(self, phase: str, plugins: tuple[str, ...]) -> None:
        count = len(plugins)
        if phase == "CONCURRENT":
            self.logger.info(
                f"[runner] Ortalık karışacak yeğenim! {count} eklenti "
                "aynı anda çalışıyor, sıkı dur..."
            )
        else:
            self.logger.info(
                f"[runner] {phase} turu başladı yeğenim; "
                f"{count} eklenti sırada."
            )

    def phase_finished(self, phase: str) -> None:
        self.logger.info(f"[runner] {phase} turu tamamlandı yeğenim.")

    def show_artifact(self, message: str) -> None:
        log_artifact(self.logger, message)

    def show_flag(self, flag: str, source: str | None = None) -> None:
        if not self._flag_banner_shown:
            log_found(self.logger, FLAG_FOUND_BANNER)
            self._flag_banner_shown = True
        suffix = f" ← {source}" if source else ""
        log_found(self.logger, f"    🚩 {flag}{suffix}")

    def show_warning(self, message: str) -> None:
        self.logger.warning(message)

    def show_no_flags(self) -> None:
        self.logger.warning(NO_FLAG_BANNER)


@dataclass(frozen=True)
class _RichComponents:
    """Late-imported Rich classes, grouped for dependency-free testing."""

    Console: Any
    Panel: Any
    Table: Any
    Text: Any
    Progress: Any
    SpinnerColumn: Any
    TextColumn: Any
    BarColumn: Any
    TaskProgressColumn: Any
    TimeElapsedColumn: Any
    RichHandler: Any


def _load_rich_components() -> _RichComponents | None:
    """Import Rich lazily, returning None when the optional extra is absent."""
    try:
        from rich.console import Console
        from rich.logging import RichHandler
        from rich.panel import Panel
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TaskProgressColumn,
            TextColumn,
            TimeElapsedColumn,
        )
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        return None

    return _RichComponents(
        Console=Console,
        Panel=Panel,
        Table=Table,
        Text=Text,
        Progress=Progress,
        SpinnerColumn=SpinnerColumn,
        TextColumn=TextColumn,
        BarColumn=BarColumn,
        TaskProgressColumn=TaskProgressColumn,
        TimeElapsedColumn=TimeElapsedColumn,
        RichHandler=RichHandler,
    )


class RichTerminalUI(TerminalUI):
    """Single-owner Rich live display for phases, progress, and findings."""

    is_rich = True

    def __init__(
        self,
        logger: logging.Logger,
        stream: TextIO,
        components: _RichComponents,
    ) -> None:
        self.logger = logger
        self._components = components
        self._console = components.Console(file=stream)
        self._progress: Any | None = None
        self._task_ids: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._replaced_handlers: list[logging.Handler] = []
        self._rich_handler: logging.Handler | None = None
        self._install_logging_handler()

    def _install_logging_handler(self) -> None:
        """Route console logs through Rich so they coexist with one Live owner."""
        for handler in list(self.logger.handlers):
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                self.logger.removeHandler(handler)
                self._replaced_handlers.append(handler)

        level = min(
            (handler.level for handler in self._replaced_handlers),
            default=self.logger.level,
        )
        try:
            rich_handler = self._components.RichHandler(
                console=self._console,
                show_time=False,
                show_level=False,
                show_path=False,
                markup=False,
                rich_tracebacks=False,
            )
            rich_handler.setLevel(level)
            rich_handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(rich_handler)
            self._rich_handler = rich_handler
        except Exception:
            for handler in self._replaced_handlers:
                self.logger.addHandler(handler)
            self._replaced_handlers.clear()
            raise

    def _start_progress(self) -> None:
        if self._progress is not None:
            return
        progress = self._components.Progress(
            self._components.SpinnerColumn(),
            self._components.TextColumn("{task.description}"),
            self._components.BarColumn(),
            self._components.TaskProgressColumn(),
            self._components.TimeElapsedColumn(),
            console=self._console,
            transient=False,
        )
        progress.start()
        self._progress = progress

    def phase_started(self, phase: str, plugins: tuple[str, ...]) -> None:
        with self._lock:
            self._stop_progress()
            self._start_progress()
            assert self._progress is not None
            self._task_ids = {
                plugin_id: self._progress.add_task(
                    f"[cyan]⠋[/cyan] {plugin_id} [dim]({phase})[/dim]",
                    total=None,
                )
                for plugin_id in plugins
            }

    def phase_finished(self, phase: str) -> None:
        with self._lock:
            self._stop_progress()

    def plugin_started(self, plugin_id: str) -> None:
        with self._lock:
            self._start_progress()
            assert self._progress is not None
            task_id = self._task_ids.get(plugin_id)
            if task_id is None:
                task_id = self._progress.add_task(plugin_id, total=None)
                self._task_ids[plugin_id] = task_id
            self._progress.update(
                task_id,
                description=f"[cyan]⠋[/cyan] {plugin_id}",
            )

    def plugin_progress(
        self,
        plugin_id: str,
        attempted: int,
        total: int | None,
    ) -> None:
        with self._lock:
            self.plugin_started(plugin_id)
            assert self._progress is not None
            task_id = self._task_ids[plugin_id]
            update: dict[str, Any] = {
                "completed": attempted,
                "description": f"[cyan]⠋[/cyan] {plugin_id}: {attempted} deneme",
            }
            if total is not None:
                update["total"] = max(total, attempted, 1)
            self._progress.update(task_id, **update)

    def plugin_finished(self, plugin_id: str, outcome: str) -> None:
        styles = {
            "complete": ("[green]✓[/green]", "green"),
            "skipped": ("[yellow]↷[/yellow]", "yellow"),
            "timed_out": ("[yellow]⌛[/yellow]", "yellow"),
            "cancelled": ("[yellow]■[/yellow]", "yellow"),
            "failed": ("[red]✗[/red]", "red"),
        }
        marker, style = styles.get(outcome, ("[green]✓[/green]", "green"))
        with self._lock:
            self._start_progress()
            assert self._progress is not None
            task_id = self._task_ids.get(plugin_id)
            if task_id is None:
                task_id = self._progress.add_task(plugin_id, total=1)
                self._task_ids[plugin_id] = task_id
            self._progress.update(
                task_id,
                completed=1,
                total=1,
                description=f"{marker} [{style}]{plugin_id}[/{style}]",
            )

    def show_artifact(self, message: str) -> None:
        with self._lock:
            self._console.print(
                self._components.Panel(
                    self._components.Text(message),
                    title="[bold dark_orange]Dayı İpucu[/bold dark_orange]",
                    border_style="dark_orange",
                    expand=False,
                )
            )

    def show_flag(self, flag: str, source: str | None = None) -> None:
        with self._lock:
            table = self._components.Table(
                title="🎯 FLAG BULUNDU — İşte bu yeğenim!",
                border_style="gold1",
                title_style="bold green",
                show_header=True,
            )
            table.add_column("Flag", style="bold bright_green")
            table.add_column("Kaynak", style="cyan")
            table.add_row(
                self._components.Text(flag, style="bold bright_green"),
                self._components.Text(source or "Dayı taraması", style="cyan"),
            )
            self._console.print(table)

    def show_warning(self, message: str) -> None:
        with self._lock:
            self._console.print(
                self._components.Panel(
                    self._components.Text(message),
                    title="[bold red]Dayı Uyarısı[/bold red]",
                    border_style="red",
                    expand=False,
                )
            )

    def show_no_flags(self) -> None:
        with self._lock:
            self._console.print(
                self._components.Panel(
                    self._components.Text(
                        "Flag bulunamadı. Ama Dayı'nın raporu hazır; "
                        "manuel incelemeye geçebilirsin yeğenim."
                    ),
                    title="[bold yellow]Tarama Tamamlandı[/bold yellow]",
                    border_style="yellow",
                    expand=False,
                )
            )

    def _stop_progress(self) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
            self._task_ids.clear()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._stop_progress()
            if self._rich_handler is not None:
                self.logger.removeHandler(self._rich_handler)
                self._rich_handler.close()
                self._rich_handler = None
            for handler in self._replaced_handlers:
                self.logger.addHandler(handler)
            self._replaced_handlers.clear()
            self._closed = True


def create_terminal_ui(
    logger: logging.Logger | None = None,
    stream: TextIO | None = None,
) -> TerminalUI:
    """Select Rich only when installed and attached to an interactive TTY."""
    app_logger = logger or logging.getLogger("dayi")
    output = stream or sys.stdout
    try:
        interactive = bool(output.isatty())
    except (AttributeError, OSError):
        interactive = False
    if not interactive:
        return PlainTerminalUI(app_logger)

    components = _load_rich_components()
    if components is None:
        return PlainTerminalUI(app_logger)
    try:
        return RichTerminalUI(app_logger, output, components)
    except Exception as exc:
        app_logger.warning(
            "[!] Yeğenim Rich arayüzü kurulamadı; düz ekrana dönüyorum. "
            f"({exc})"
        )
        return PlainTerminalUI(app_logger)
