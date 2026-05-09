#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_DIR = Path(__file__).resolve().parent
DB_DIR = PROJECT_DIR / "db"
LOG_DIR = PROJECT_DIR / "logs"
REPORT_DIR = PROJECT_DIR / "reports"
DEFAULT_LIST = PROJECT_DIR / "critical_files.txt"
DEFAULT_EXCLUDE = PROJECT_DIR / "exclude.txt"
BASELINE = DB_DIR / "baseline.sha256"
LAST_SCAN = DB_DIR / "last_scan.sha256"
LOG_FILE = LOG_DIR / "fic.log"

LOG_PATH = LOG_FILE
CHUNK_SIZE = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{ts()}] {message}"
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    print(line)


def die(message: str, code: int = 1) -> None:
    log(f"ERROR: {message}")
    raise SystemExit(code)


def ensure_default_list() -> None:
    if DEFAULT_LIST.exists():
        return

    DEFAULT_LIST.write_text(
        "\n".join(
            [
                "# One file per line.",
                "# Lines starting with # are comments (ignored).",
                "# This default list is project-local and works on Windows/Linux.",
                "# You can add absolute paths if you want it to work from any directory.",
                "",
                "# This script file:",
                str(PROJECT_DIR / "fic.py"),
                "",
                "# Optional: track this list file too:",
                str(DEFAULT_LIST),
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    log(f"Created default list: {DEFAULT_LIST}")
    log("Edit it if needed, then run: python fic.py init")


def read_simple_list(path: Path) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        die(f"List file not found: {path}")

    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def read_exclude_file(path: Path) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        die(f"Exclude file not found: {path}")

    patterns = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def normalize_patterns(patterns: List[str]) -> List[str]:
    norm = []
    for pat in patterns:
        pat = pat.strip()
        if not pat or pat.startswith("#"):
            continue
        norm.append(pat.replace("\\", "/"))
    return norm


def should_exclude(path: Path, patterns: List[str], case_insensitive: bool) -> bool:
    if not patterns:
        return False
    posix_path = path.as_posix()
    cmp_path = posix_path.lower() if case_insensitive else posix_path
    for pat in patterns:
        cmp_pat = pat.lower() if case_insensitive else pat
        if fnmatch(cmp_path, cmp_pat):
            return True
    return False


def safe_resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except Exception:
        return path.absolute()


def resolve_entry(entry: str, base_dir: Path) -> Path:
    entry = os.path.expandvars(entry)
    if entry.startswith("~/"):
        entry = str(Path.home() / entry[2:])
    path = Path(entry)
    if not path.is_absolute():
        path = base_dir / path
    return safe_resolve(path)


def dedupe_paths(paths: List[Path]) -> List[Path]:
    seen = set()
    out = []
    for path in paths:
        path_str = str(path)
        if path_str in seen:
            continue
        seen.add(path_str)
        out.append(path)
    return out


def collect_targets(
    listfile: Path,
    patterns: List[str],
    follow_links: bool,
) -> Tuple[List[Path], List[Path]]:
    entries = read_simple_list(listfile)
    base_dir = safe_resolve(listfile).parent
    case_insensitive = os.name == "nt"
    files: List[Path] = []
    missing: List[Path] = []

    for entry in entries:
        path = resolve_entry(entry, base_dir)
        if should_exclude(path, patterns, case_insensitive):
            continue

        if path.is_file():
            files.append(path)
            continue

        if path.is_dir():
            for root, dirs, filenames in os.walk(path, followlinks=follow_links):
                root_path = Path(root)
                pruned = []
                for dname in dirs:
                    full_dir = root_path / dname
                    if full_dir.is_symlink() and not follow_links:
                        continue
                    if should_exclude(full_dir, patterns, case_insensitive):
                        continue
                    pruned.append(dname)
                dirs[:] = pruned

                for fname in filenames:
                    full_file = root_path / fname
                    if full_file.is_symlink() and not follow_links:
                        continue
                    if should_exclude(full_file, patterns, case_insensitive):
                        continue
                    files.append(full_file)
            continue

        missing.append(path)

    return dedupe_paths(files), missing


def run_sha256sum(path: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["sha256sum", "--", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        log("WARNING: sha256sum not found; using hashlib")
        return None

    if result.returncode != 0:
        log(f"WARNING: sha256sum failed for {path}: {result.stderr.strip()}")
        return None

    parts = result.stdout.strip().split()
    return parts[0] if parts else None


def hash_with_hashlib(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_hash(path: Path, use_sha256sum: bool) -> str:
    if use_sha256sum:
        digest = run_sha256sum(path)
        if digest:
            return digest
    return hash_with_hashlib(path)


def write_hash_file(
    out_file: Path,
    files: List[Path],
    missing_entries: List[Path],
    use_sha256sum: bool,
) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    lines = []

    for path in files:
        try:
            digest = compute_hash(path, use_sha256sum)
            if digest:
                lines.append(f"{digest}  {path}")
            else:
                lines.append(f"ERROR  {path}")
        except OSError:
            lines.append(f"ERROR  {path}")

    for path in missing_entries:
        lines.append(f"MISSING  {path}")

    out_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def parse_hash_file(hash_file: Path) -> Dict[str, str]:
    if not hash_file.exists():
        die(f"File not found: {hash_file}")

    mapping: Dict[str, str] = {}
    for raw in hash_file.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\r\n")
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        h, path = parts[0], parts[1].lstrip(" *")
        mapping[path] = h
    return mapping


def compare_hashes(
    base: Dict[str, str],
    scan: Dict[str, str],
) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
    modified: List[str] = []
    missing: List[str] = []
    missing_not_scanned: List[str] = []
    errors: List[str] = []
    new: List[str] = []

    for path, bhash in sorted(base.items()):
        shash = scan.get(path)
        if shash is None:
            missing_not_scanned.append(path)
        elif shash == "MISSING":
            missing.append(path)
        elif shash == "ERROR":
            errors.append(path)
        elif bhash != shash:
            modified.append(path)

    for path in sorted(scan.keys() - base.keys()):
        new.append(path)

    summary = {
        "baseline": len(base),
        "scan": len(scan),
        "modified": len(modified),
        "missing": len(missing) + len(missing_not_scanned),
        "missing_not_scanned": len(missing_not_scanned),
        "errors": len(errors),
        "new": len(new),
    }

    changes = {
        "modified": modified,
        "missing": missing,
        "missing_not_scanned": missing_not_scanned,
        "errors": errors,
        "new": new,
    }

    return summary, changes


def format_summary(summary: Dict[str, int]) -> str:
    return (
        "baseline={baseline} scan={scan} modified={modified} missing={missing} "
        "errors={errors} new={new}"
    ).format(**summary)


def write_report(
    report_path: str,
    summary: Dict[str, int],
    changes: Dict[str, List[str]],
    append: bool = False,
) -> None:
    lines = []
    if append:
        lines.append("")
        lines.append("----")
    lines.append("File Integrity Checker Report")
    lines.append(f"Generated (UTC): {utc_now()}")
    lines.append("")
    lines.append("Summary")
    lines.append(f"- Baseline entries: {summary['baseline']}")
    lines.append(f"- Scan entries: {summary['scan']}")
    lines.append(f"- Modified: {summary['modified']}")
    lines.append(f"- Missing: {summary['missing']}")
    lines.append(f"- Errors: {summary['errors']}")
    lines.append(f"- New: {summary['new']}")
    lines.append("")

    def section(title: str, items: List[str]) -> None:
        lines.append(title)
        if items:
            lines.extend([f"- {item}" for item in items])
        else:
            lines.append("(none)")
        lines.append("")

    section("Modified files", changes["modified"])
    section("Missing files", changes["missing"])
    section("Missing (not scanned)", changes["missing_not_scanned"])
    section("Errors (could not hash)", changes["errors"])
    section("New files", changes["new"])

    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with report_path.open(mode, encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def log_changes(changes: Dict[str, List[str]]) -> None:
    for path in changes["modified"]:
        log(f"MODIFIED: {path}")
    for path in changes["missing_not_scanned"]:
        log(f"MISSING (not scanned): {path}")
    for path in changes["missing"]:
        log(f"MISSING: {path}")
    for path in changes["errors"]:
        log(f"ERROR (could not hash): {path}")
    for path in changes["new"]:
        log(f"NEW (in list now, not in baseline): {path}")


def get_excludes(args: argparse.Namespace) -> List[str]:
    patterns: List[str] = []
    if args.exclude_file:
        patterns.extend(read_exclude_file(Path(args.exclude_file)))
    elif DEFAULT_EXCLUDE.exists():
        patterns.extend(read_exclude_file(DEFAULT_EXCLUDE))
    if args.exclude:
        patterns.extend(args.exclude)
    return normalize_patterns(patterns)


def init_baseline(
    listfile: Path,
    excludes: List[str],
    follow_links: bool,
    use_sha256sum: bool,
) -> None:
    if listfile == DEFAULT_LIST and not listfile.exists():
        ensure_default_list()

    if not listfile.exists():
        die(f"List file not found: {listfile}")

    DB_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DB_DIR / ".baseline_tmp"

    files, missing_entries = collect_targets(listfile, excludes, follow_links)
    write_hash_file(tmp, files, missing_entries, use_sha256sum)
    tmp.replace(BASELINE)
    LAST_SCAN.write_text(BASELINE.read_text(encoding="utf-8"), encoding="utf-8")

    log(f"Baseline created: {BASELINE}")
    log(f"List used: {listfile}")


def run_check(
    listfile: Path,
    excludes: List[str],
    follow_links: bool,
    use_sha256sum: bool,
) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
    if not BASELINE.exists():
        die("Baseline not found. Run: python fic.py init")

    DB_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DB_DIR / ".scan_tmp"

    files, missing_entries = collect_targets(listfile, excludes, follow_links)
    write_hash_file(tmp, files, missing_entries, use_sha256sum)
    tmp.replace(LAST_SCAN)

    base = parse_hash_file(BASELINE)
    scan = parse_hash_file(LAST_SCAN)
    return compare_hashes(base, scan)


def cmd_add(path: str, listfile: Path) -> None:
    if listfile == DEFAULT_LIST and not listfile.exists():
        ensure_default_list()

    if not listfile.exists():
        die(f"List file not found: {listfile}")

    existing = listfile.read_text(encoding="utf-8").splitlines()
    if any(line.strip() == path for line in existing):
        log(f"Already in list: {path}")
        return

    with listfile.open("a", encoding="utf-8") as handle:
        if existing and existing[-1] != "":
            handle.write("\n")
        handle.write(path + "\n")

    log(f"Added to list: {path}")


def cmd_remove(path: str, listfile: Path) -> None:
    if not listfile.exists():
        die(f"List file not found: {listfile}")

    lines = listfile.read_text(encoding="utf-8").splitlines()
    new_lines = [ln for ln in lines if ln.strip() != path]
    listfile.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    log(f"Removed from list: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fic.py",
        description="File Integrity Checker (SHA-256)",
    )
    parser.add_argument("--version", action="version", version="fic 1.0")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--exclude-file", help="Exclude patterns file")
    common.add_argument("--exclude", action="append", help="Exclude pattern")
    common.add_argument("--follow-links", action="store_true", help="Follow symlinks")
    common.add_argument("--sha256sum", action="store_true", help="Use sha256sum if available")
    common.add_argument("--log", help="Log file path")

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_init = subparsers.add_parser("init", parents=[common], help="Create baseline hashes")
    p_init.add_argument("listfile", nargs="?", default=str(DEFAULT_LIST))

    p_check = subparsers.add_parser("check", parents=[common], help="Compare current hashes vs baseline")
    p_check.add_argument("listfile", nargs="?", default=str(DEFAULT_LIST))
    p_check.add_argument("--report", help="Write report to a file")
    p_check.add_argument(
        "--fail-on-change",
        action="store_true",
        help="Exit with code 2 if changes are detected",
    )

    p_monitor = subparsers.add_parser("monitor", parents=[common], help="Monitor integrity")
    p_monitor.add_argument("listfile", nargs="?", default=str(DEFAULT_LIST))
    p_monitor.add_argument("--interval", type=int, default=60, help="Seconds between checks")
    p_monitor.add_argument("--report", help="Append report output to a file")

    p_add = subparsers.add_parser("add", help="Add file path to list")
    p_add.add_argument("path")
    p_add.add_argument("listfile", nargs="?", default=str(DEFAULT_LIST))

    p_remove = subparsers.add_parser("remove", help="Remove file path from list")
    p_remove.add_argument("path")
    p_remove.add_argument("listfile", nargs="?", default=str(DEFAULT_LIST))

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    global LOG_PATH
    LOG_PATH = Path(args.log) if getattr(args, "log", None) else LOG_FILE

    cmd = args.cmd

    if cmd == "add":
        cmd_add(args.path, Path(args.listfile))
        return 0
    if cmd == "remove":
        cmd_remove(args.path, Path(args.listfile))
        return 0

    listfile = Path(args.listfile)
    excludes = get_excludes(args)

    if cmd == "init":
        init_baseline(listfile, excludes, args.follow_links, args.sha256sum)
        return 0

    if cmd == "check":
        summary, changes = run_check(listfile, excludes, args.follow_links, args.sha256sum)
        log("Scan complete. Comparing with baseline...")
        log_changes(changes)

        change_count = summary["modified"] + summary["missing"] + summary["errors"] + summary["new"]
        if change_count == 0:
            log("OK: No changes detected.")
        else:
            log(f"ALERT: Detected {change_count} change(s). See log: {LOG_PATH}")

        log(f"SUMMARY: {format_summary(summary)}")

        if args.report:
            write_report(args.report, summary, changes, append=False)

        if args.fail_on_change and change_count > 0:
            return 2
        return 0

    if cmd == "monitor":
        if args.interval <= 0:
            die("Interval must be greater than 0")

        log(f"Monitoring started (interval={args.interval}s)")
        try:
            while True:
                summary, changes = run_check(
                    listfile,
                    excludes,
                    args.follow_links,
                    args.sha256sum,
                )
                log(f"SUMMARY: {format_summary(summary)}")

                change_count = (
                    summary["modified"] + summary["missing"] + summary["errors"] + summary["new"]
                )
                if change_count > 0:
                    log_changes(changes)
                    log(f"ALERT: Detected {change_count} change(s). See log: {LOG_PATH}")

                if args.report:
                    write_report(args.report, summary, changes, append=True)

                time.sleep(args.interval)
        except KeyboardInterrupt:
            log("Monitoring stopped")
            return 0

    die(f"Unknown command: {cmd}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
