"""
dayi/cli.py
~~~~~~~~~~~~
Entry point for the Dayı Stego Solver CLI — v3.0.

New in v3.0:
  --writeup  : Generate an automatic Markdown writeup after the scan.
               Integrates with ctfshit.src.writeup_exporter if available;
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

ARGPARSE FLEXIBILITY: Uses parse_intermixed_args() — the positional target
    file can appear anywhere in the argument list.

GRACEFUL SHUTDOWN: KeyboardInterrupt → asyncio task cancelled → integration
    drained → partial report written → exit 130 (SIGINT convention).
"""
import argparse
import asyncio
import sys
from pathlib import Path

from dayi.persona import BANNER, setup_logger
from dayi.scanner import compile_pattern
from dayi.runner import DayiRunner
from dayi.reporter import ScanReport, write_report, export_markdown_writeup
from dayi.integrations import build_integration, IntegrationManager


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="dayi",
        description="Dayı Stego Solver v3.0 — CTF Steganography Brute-force & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler / Examples:
  # Temel kullanım
  dayi photo.jpg --flag "CTF{.*?}" --wordlist rockyou.txt --output rapor

  # Otomatik write-up ile
  dayi stego.png --flag "picoCTF{.*?}" --writeup writeup.md

  # CTFd + Discord + write-up
  dayi stego.png --flag "picoCTF{.*?}" \\
      --ctfd-url https://ctf.example.com --ctfd-token TOKEN123 \\
      --challenge-id 42 --webhook https://discord.com/api/webhooks/… \\
      --writeup stego_writeup.md

  # Parametre sırası esnekliği (dosya sonda da olabilir)
  dayi --flag "FLAG{.*?}" --output sonuc --format json image.png
        """,
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
        required=True,
        help='Aranacak flag regex deseni. Örnek: "CTF{.*?}" veya "picoCTF{[^}]+}"',
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
        "--format",
        choices=["txt", "json"],
        default="txt",
        help="Rapor formatı: txt (varsayılan) veya json",
    )
    parser.add_argument(
        "--timeout", "-t",
        metavar="SANIYE",
        type=float,
        default=60.0,
        help="Her araç için maksimum bekleme süresi (saniye). Varsayılan: 60",
    )
    parser.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=8,
        help="Brute-force için eş zamanlı işlem sayısı. Varsayılan: 8",
    )
    parser.add_argument(
        "--bf-limit",
        metavar="N",
        type=int,
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
        default="",
        help=(
            "Discord incoming webhook URL. "
            "Bulunan her flag için embed mesaj gönderir."
        ),
    )
    integration_group.add_argument(
        "--ctfd-url",
        metavar="URL",
        type=str,
        default="",
        help="CTFd platform URL (örn: https://ctf.example.com). Flag otomatik gönderilir.",
    )
    integration_group.add_argument(
        "--ctfd-token",
        metavar="TOKEN",
        type=str,
        default="",
        help="CTFd API token (Profil → API Token sayfasından alınır).",
    )
    integration_group.add_argument(
        "--challenge-id",
        metavar="ID",
        type=int,
        default=0,
        help="CTFd challenge ID'si. Flag bu challenge'a karşı gönderilir.",
    )
    integration_group.add_argument(
        "--challenge-name",
        metavar="NAME",
        type=str,
        default="Dayı Auto-Solve",
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

    return parser


async def _run_analysis(args: argparse.Namespace, logger) -> tuple[ScanReport | None, int]:
    """
    Core async analysis logic, separated for clean Ctrl+C handling.

    Constructs the optional FlagIntegration from CLI args and wires it into
    DayiRunner so notifications are dispatched as flags are found.

    Args:
        args:   Parsed CLI arguments (from parse_intermixed_args).
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

    pattern = compile_pattern(args.flag)
    if pattern is None:
        logger.error(
            "[✗] Geçersiz regex deseni! Düzgün bir tane ver bana, ben büyücü değilim."
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
    logger.info(f"[*] Flag deseni   : {args.flag}")
    logger.info(f"[*] Wordlist      : {wordlist or 'Belirtilmedi'}")
    logger.info(f"[*] Timeout       : {args.timeout}s per tool")
    logger.info(f"[*] BF Threads    : {args.threads}")
    logger.info(f"[*] BF Limit      : {args.bf_limit if args.bf_limit else 'Sınırsız (dikkat!)'}")
    if integration:
        logger.info(f"[*] CTFd URL      : {args.ctfd_url or 'Devre dışı'}")
        logger.info(f"[*] Webhook       : {'Aktif' if args.webhook else 'Devre dışı'}")
        logger.info(f"[*] Challenge ID  : {args.challenge_id or 'Belirtilmedi'}")
    logger.info("")

    runner = DayiRunner(
        target=target,
        pattern=pattern,
        wordlist=wordlist,
        timeout=args.timeout,
        bf_threads=args.threads,
        bf_limit=args.bf_limit,
        integration=integration,
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
        report = runner._build_report()
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
            logger.info("[*] Write-up hazırlanıyor... Dayı kalemini eline aldı yeğenim!")
            export_markdown_writeup(report, writeup_path)

    return exit_code


def main() -> None:
    """
    Synchronous CLI entry point.

    Uses parse_intermixed_args() so the positional DOSYA argument can appear
    anywhere in the command line relative to the optional arguments.
    """
    parser = build_arg_parser()

    try:
        args = parser.parse_intermixed_args()
    except SystemExit:
        raise  # Let argparse handle --help and genuine errors normally

    try:
        exit_code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[!] Yeğenim, Ctrl+C aldım. Çıkıyorum ama raporu yazdım!")
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
