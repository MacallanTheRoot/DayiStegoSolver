"""
dayi/cli.py
~~~~~~~~~~~~
Entry point for the Dayı Stego Solver CLI — v3.0.

New in v3.0:
  --writeup  : Generate an automatic Markdown writeup after the scan.
               Integrates with the optional ctfshit exporter if available;
               falls back to a built-in Markdown generator otherwise.

New in v2.0:
  --webhook     : Discord incoming webhook URL for real-time flag notifications.
  --ctfd-url    : CTFd platform URL for automatic flag submission.
  --ctfd-token  : CTFd API token (Token <value>).
  --challenge-id: CTFd challenge ID to submit found flags against.
  --challenge-name: Human-readable challenge name (appears in Discord embed).

Integration is opt-in: if none of the above are provided, the tool behaves
exactly as v1.x. When configured, each found flag is dispatched immediately
(fire-and-forget) without waiting for the scan to finish.

ARGPARSE FLEXIBILITY: The explicit ``scan`` command and a small legacy argv
    normalizer share one scan parser and one execution path.

GRACEFUL SHUTDOWN: KeyboardInterrupt → asyncio task cancelled → integration
    drained → partial report written → exit 130 (SIGINT convention).
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

from dayi import __version__
from dayi.doctor import doctor_exit_code, render_json, render_plain, run_diagnostics
from dayi.plugin_inspector import (
    inspect_plugins,
    render_json as render_plugins_json,
    render_plain as render_plugins_plain,
)
from dayi.persona import BANNER, setup_logger
from dayi.scanner import build_flag_pattern_config
from dayi.runner import (
    DayiRunner,
    WorkspaceConfigurationError,
    validate_workspace_parent,
)
from dayi.reporter import ScanReport, write_report, export_markdown_writeup
from dayi.integrations import build_integration


def _positive_float(value: str) -> float:
    """Parse a strictly positive floating-point CLI value."""
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    """Parse a strictly positive integer CLI value."""
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _nonnegative_int(value: str) -> int:
    """Parse a non-negative integer CLI value."""
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return parsed


def _build_scan_parent_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Core arguments ────────────────────────────────────────────────────────
    parser.add_argument(
        "target",
        metavar="DOSYA",
        type=Path,
        help="Analiz edilecek hedef dosya (görsel, ses, vb.)",
    )
    parser.add_argument(
        "--flag", "-f",
        metavar="REGEX",
        default=None,
        help=(
            "Aranacak özel flag regex deseni. Verilmezse yerleşik yaygın CTF "
            "desenleri kullanılır"
        ),
    )
    parser.add_argument(
        "--wordlist", "-w",
        metavar="WORDLIST",
        type=Path,
        default=None,
        help="Şifreli araçlar için wordlist dosyası (örn: rockyou.txt)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="ÇIKTI",
        type=Path,
        default=Path("dayi_rapor"),
        help="Çıktı dosyasının adı (uzantısız). Varsayılan: dayi_rapor",
    )
    parser.add_argument(
        "--workspace-dir",
        metavar="PATH",
        type=Path,
        default=None,
        help=(
            "Benzersiz analiz çalışma alanlarının oluşturulacağı üst klasör. "
            "Varsayılan: sistem geçici dizini"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["txt", "json"],
        default="txt",
        help="Rapor formatı: txt (varsayılan) veya json",
    )
    parser.add_argument(
        "--timeout", "-t",
        metavar="SANIYE",
        type=_positive_float,
        default=60.0,
        help="Her araç için maksimum bekleme süresi (saniye). Varsayılan: 60",
    )
    parser.add_argument(
        "--threads",
        metavar="N",
        type=_positive_int,
        default=8,
        help="Brute-force için eş zamanlı işlem sayısı. Varsayılan: 8",
    )
    parser.add_argument(
        "--bf-limit",
        metavar="N",
        type=_nonnegative_int,
        default=1000,
        help=(
            "Python brute-force araçları (steghide_bf, outguess_bf) için "
            "denenecek maksimum şifre sayısı. 0 = sınırsız (tehlikeli!). "
            "Varsayılan: 1000. stegseek sınırı yok, onunla dene."
        ),
    )
    parser.add_argument(
        "--log-file",
        metavar="LOG",
        type=str,
        default=None,
        help="Log dosyası yolu (isteğe bağlı)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Ayrıntılı debug çıktısı",
    )

    # ── v2.0 Integration arguments ────────────────────────────────────────────
    integration_group = parser.add_argument_group(
        "Otomasyon / Integration (v2.0)",
        "Flag bulunduğunda anında CTFd'ye gönder veya Discord'a bildir.",
    )
    integration_group.add_argument(
        "--webhook",
        metavar="URL",
        type=str,
        default=None,
        help=(
            "Discord incoming webhook URL. "
            "Bulunan her flag için embed mesaj gönderir. Gizli değerler için "
            "DAYI_DISCORD_WEBHOOK_URL kullanılması önerilir."
        ),
    )
    integration_group.add_argument(
        "--ctfd-url",
        metavar="URL",
        type=str,
        default=None,
        help="CTFd platform URL (örn: https://ctf.example.com). Flag otomatik gönderilir.",
    )
    integration_group.add_argument(
        "--ctfd-token",
        metavar="TOKEN",
        type=str,
        default=None,
        help=(
            "CTFd API token (Profil → API Token sayfasından alınır). Gizli değerler "
            "için DAYI_CTFD_TOKEN kullanılması önerilir."
        ),
    )
    integration_group.add_argument(
        "--challenge-id",
        metavar="ID",
        type=int,
        default=None,
        help="CTFd challenge ID'si. Flag bu challenge'a karşı gönderilir.",
    )
    integration_group.add_argument(
        "--challenge-name",
        metavar="NAME",
        type=str,
        default=None,
        help="Challenge adı (Discord embed'de görünür). Varsayılan: 'Dayı Auto-Solve'",
    )

    # ── v3.0 Writeup argument ─────────────────────────────────────────────────
    writeup_group = parser.add_argument_group(
        "Write-up Üretimi (v3.0)",
        "Analiz bittikten sonra otomatik Markdown write-up belgesi oluştur.",
    )
    writeup_group.add_argument(
        "--writeup",
        metavar="WRITEUP.md",
        type=Path,
        default=None,
        help=(
            "Otomatik Markdown write-up dosyasının kaydedileceği yol. "
            "Örn: writeup.md — ctfshit varsa zengin format, yoksa yedek format kullanılır."
        ),
    )
    writeup_group.add_argument(
        "--ctfshit-path",
        metavar="PATH",
        type=Path,
        default=None,
        help=(
            "İsteğe bağlı ctfshitcli checkout yolu. Verilmezse "
            "DAYI_CTFSHIT_PATH ve otomatik çözümleme kullanılır."
        ),
    )

    return parser


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the top-level parser and its explicit scan command."""
    parser = argparse.ArgumentParser(
        prog="dayi",
        description=(
            f"Dayı Stego Solver v{__version__} — "
            "CTF Steganography Brute-force & Analysis Tool"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    scan_parser = subparsers.add_parser(
        "scan",
        parents=[_build_scan_parent_parser()],
        help="Bir hedef dosyada steganografi ve forensics taraması çalıştır",
        description=(
            "Hedef dosyayı tara. --flag verilmezse Dayı yaygın CTF flag "
            "öneklerini muhafazakâr biçimde arar."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler / Examples:
  dayi scan photo.jpg
  dayi scan photo.jpg --flag "CTF{.*?}" --wordlist rockyou.txt
  dayi scan --flag "FLAG{.*?}" --output sonuc --format json image.png
        """,
    )
    scan_parser.set_defaults(command="scan")
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Çekirdek kurulumu ve isteğe bağlı kabiliyetleri denetle",
        description=(
            "Ağ erişimi veya hedef taraması yapmadan Python, paket, harici "
            "araç ve isteğe bağlı modül durumunu denetle."
        ),
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Tanı sonucunu kararlı JSON olarak stdout'a yaz",
    )
    doctor_parser.add_argument(
        "--ctfshit-path",
        metavar="PATH",
        type=Path,
        default=None,
        help=(
            "Doctor için isteğe bağlı ctfshitcli checkout yolu. Verilmezse "
            "DAYI_CTFSHIT_PATH ve otomatik çözümleme kullanılır."
        ),
    )
    doctor_parser.set_defaults(command="doctor")
    plugins_parser = subparsers.add_parser(
        "plugins",
        help="Dinamik eklenti registry'sini güvenli biçimde incele",
        description=(
            "Paket içindeki güvenilir eklenti tanımlarını keşfet; runner veya "
            "harici araç çalıştırmadan kayıt ve uygunluk durumunu göster."
        ),
    )
    plugin_actions = plugins_parser.add_subparsers(
        dest="plugins_action",
        metavar="ACTION",
        required=True,
    )
    plugins_list_parser = plugin_actions.add_parser(
        "list",
        help="Kayıtlı eklentileri ve keşif sorunlarını listele",
    )
    plugins_list_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Eklenti listesini kararlı JSON olarak stdout'a yaz",
    )
    plugins_list_parser.set_defaults(command="plugins", plugins_action="list")
    return parser


def normalize_cli_argv(argv: list[str]) -> list[str]:
    """Map the legacy flat scan syntax onto the explicit scan command."""
    tokens = list(argv)
    if not tokens:
        return ["scan"]
    if tokens[0] in {"-h", "--help", "--version"}:
        return tokens
    if tokens[0] in {"scan", "doctor", "plugins"}:
        return tokens
    return ["scan", *tokens]


def parse_cli_args(
    argv: list[str] | None = None,
    parser: argparse.ArgumentParser | None = None,
) -> argparse.Namespace:
    """Parse explicit or legacy scan arguments into one shared namespace."""
    active_parser = parser if parser is not None else build_arg_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    return active_parser.parse_args(normalize_cli_argv(raw_args))


def _select_ctfshit_path(cli_path: Path | None) -> tuple[Path | None, str | None]:
    """Select one authoritative explicit ctfshit checkout path."""
    if cli_path is not None:
        return cli_path, "cli"

    environment_value = os.environ.get("DAYI_CTFSHIT_PATH")
    if environment_value is None or not environment_value.strip():
        return None, None
    return Path(environment_value.strip()), "environment"


async def _run_analysis(args: argparse.Namespace, logger) -> tuple[ScanReport | None, int]:
    """
    Core async analysis logic, separated for clean Ctrl+C handling.

    Constructs the optional FlagIntegration from CLI args and wires it into
    DayiRunner so notifications are dispatched as flags are found.

    Args:
        args:   Parsed CLI arguments for the shared scan execution path.
        logger: Configured logger instance.

    Returns:
        Tuple of (ScanReport or None on fatal error, exit_code).
    """
    target: Path = args.target.resolve()

    # ── Input validation ──────────────────────────────────────────────────────
    if not target.exists():
        logger.error(
            f"[✗] Yeğenim '{target}' diye bir dosya yok ortada. Doğru yolu ver bana!"
        )
        return None, 1

    if not target.is_file():
        logger.error(f"[✗] '{target}' bir dosya değil. Klasör mü verdin bana?!")
        return None, 1

    wordlist: Path | None = None
    if args.wordlist:
        if not args.wordlist.exists():
            logger.warning(
                f"[!] Wordlist '{args.wordlist}' bulunamadı. Brute-force atlanacak, dikkat!"
            )
        else:
            wordlist = args.wordlist

    pattern_config = build_flag_pattern_config(args.flag)
    if pattern_config is None:
        logger.error(
            "[✗] Geçersiz regex deseni! Düzgün bir tane ver bana, ben büyücü değilim."
        )
        return None, 1

    workspace_parent: Path | None = None
    if args.workspace_dir is not None:
        try:
            workspace_parent = validate_workspace_parent(args.workspace_dir)
        except WorkspaceConfigurationError as exc:
            logger.error(
                "[✗] Yeğenim çalışma alanı klasörü hazırlanamadı: "
                f"{exc}. Yazılabilir bir klasör ver."
            )
            return None, 1

    # ── Integration setup ─────────────────────────────────────────────────────
    integration = build_integration(
        webhook_url=args.webhook,
        ctfd_url=args.ctfd_url,
        ctfd_token=args.ctfd_token,
        challenge_id=args.challenge_id,
        challenge_name=args.challenge_name,
    )

    # ── Summary log ───────────────────────────────────────────────────────────
    logger.info(f"[*] Hedef dosya   : {target}")
    logger.info(f"[*] Flag deseni   : {pattern_config.display}")
    logger.info(f"[*] Desen kaynağı : {pattern_config.source}")
    logger.info(f"[*] Wordlist      : {wordlist or 'Belirtilmedi'}")
    logger.info(f"[*] Timeout       : {args.timeout}s per tool")
    logger.info(f"[*] BF Threads    : {args.threads}")
    logger.info(f"[*] BF Limit      : {args.bf_limit if args.bf_limit else 'Sınırsız (dikkat!)'}")
    logger.info(
        f"[*] Workspace üstü: {workspace_parent or 'Sistem geçici dizini'}"
    )
    if integration:
        channels = getattr(integration, "configured_channels", ())
        if not isinstance(channels, tuple):
            channels = ()
        logger.info(f"[*] CTFd          : {'Aktif' if 'ctfd' in channels else 'Devre dışı'}")
        logger.info(
            f"[*] Webhook       : {'Aktif' if 'discord' in channels else 'Devre dışı'}"
        )
        logger.info(
            f"[*] Challenge ID  : {'Yapılandırıldı' if 'ctfd' in channels else 'Belirtilmedi'}"
        )
    logger.info("")

    runner = DayiRunner(
        target=target,
        pattern=pattern_config.compiled,
        wordlist=wordlist,
        timeout=args.timeout,
        bf_threads=args.threads,
        bf_limit=args.bf_limit,
        integration=integration,
        workspace_parent=workspace_parent,
        pattern_display=pattern_config.display,
        pattern_source=pattern_config.source,
    )

    logger.info("[*] Tarama başlıyor... Sabret yeğenim, Dayı çalışıyor.\n")

    # Wrap run_all in a Task for clean Ctrl+C cancellation
    task = asyncio.create_task(runner.run_all())
    try:
        report = await task
        return report, 0
    except asyncio.CancelledError:
        # run_all() caught CancelledError, drained integration, and built a
        # partial report — retrieve it via _build_report() as final fallback.
        report = runner._last_report or runner._build_report()
        return report, 130


async def async_main(args: argparse.Namespace) -> int:
    """
    Async entry point: configures logger, dispatches analysis, writes report.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code.
    """
    logger = setup_logger(
        name="dayi",
        log_file=args.log_file,
        verbose=args.verbose,
    )

    logger.info(BANNER)
    logger.info(
        "[*] Hazırım yeğenim! Dosyayı teslim et, gerisini Dayı halleder...\n"
    )

    report, exit_code = await _run_analysis(args, logger)

    if report is not None:
        output_path: Path = args.output
        write_report(report, output_path, fmt=args.format)
        suffix = ".json" if args.format == "json" else ".txt"
        logger.info(f"\n[✓] Rapor hazır yeğenim! → {output_path}{suffix}")

        # ── v3.0 Writeup generation ───────────────────────────────────────────
        if args.writeup is not None:
            writeup_path: Path = args.writeup
            if writeup_path.suffix.lower() != ".md":
                writeup_path = writeup_path.with_suffix(".md")
            ctfshit_path, ctfshit_source = _select_ctfshit_path(args.ctfshit_path)
            if ctfshit_source == "cli":
                logger.debug("[*] Açık ctfshit yolu seçildi.")
            elif ctfshit_source == "environment":
                logger.debug("[*] DAYI_CTFSHIT_PATH seçildi.")
            logger.info("[*] Write-up hazırlanıyor... Dayı kalemini eline aldı yeğenim!")
            export_markdown_writeup(
                report,
                writeup_path,
                ctfshit_path=ctfshit_path,
            )

    return exit_code


def main() -> None:
    """
    Synchronous CLI entry point.

    Normalizes the legacy flat syntax into the explicit scan command before
    parsing so both forms use the same analysis implementation.
    """
    parser = build_arg_parser()

    try:
        args = parse_cli_args(parser=parser)
    except SystemExit:
        raise  # Let argparse handle --help and genuine errors normally

    if args.command == "doctor":
        ctfshit_path, ctfshit_source = _select_ctfshit_path(args.ctfshit_path)
        report = run_diagnostics(
            ctfshit_path=ctfshit_path,
            ctfshit_path_source=ctfshit_source,
        )
        rendered = render_json(report) if args.json_output else render_plain(report)
        print(rendered)
        sys.exit(doctor_exit_code(report))

    if args.command == "plugins":
        try:
            report = inspect_plugins()
        except Exception as exc:
            print(
                f"[✗] Yeğenim eklenti registry'si incelenemedi: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)
        rendered = (
            render_plugins_json(report)
            if args.json_output
            else render_plugins_plain(report)
        )
        print(rendered)
        sys.exit(0)

    try:
        exit_code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[!] Yeğenim, Ctrl+C aldım. Çıkıyorum ama raporu yazdım!")
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
