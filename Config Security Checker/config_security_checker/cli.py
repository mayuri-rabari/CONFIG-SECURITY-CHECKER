#!/usr/bin/env python3
"""
CLI entrypoint for the professional Config Security Checker.
"""
import argparse
import sys
from pathlib import Path
from .scanner import Scanner
from .output.printer import print_results_console, dump_results_console
from .output.json_output import dump_results_json

def build_parser():
    p = argparse.ArgumentParser(prog="config-checker", description="Config Security Checker - Professional Engine")
    p.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks")
    p.add_argument("--json", action="store_true", help="Output JSON to stdout")
    p.add_argument("--pretty/--no-pretty", dest="pretty", default=True, help="Rich pretty output")
    p.add_argument("--max-size", type=int, default=300_000, help="Max file size to scan (bytes)")
    p.add_argument("--exclude", "-x", action="append", default=[], help="Exclude path/glob (can repeat)")
    p.add_argument("--allowlist", "-a", type=str, help="Path to allowlist file (one glob/regex per line). Lines starting with # are ignored.")
    p.add_argument("--min-score", type=int, default=7, help="Minimum score to show (0..10). Default 7 (high-confidence only).")
    p.add_argument("--types", type=str, default="", help="Comma-separated types to include (secret,weak-cipher,pem). Empty = all")
    p.add_argument("--save-report", type=str, help="Write JSON report to given path")
    p.add_argument("--aggressive", action="store_true", help="Enable aggressive detection mode (more noisy; for hunting)")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        print("Target not found", file=sys.stderr)
        sys.exit(2)

    # default excludes: noisy folders and known signature datasets
    default_excludes = [
        ".venv", "venv", "node_modules", "__pycache__", ".git", "tests", "examples",
        "VersionTables", "Checksums", "Hashes", "Signatures", "ScanData", "VersionTables*",
    ]
    excludes = list(default_excludes) + args.exclude

    types = [t.strip() for t in args.types.split(",") if t.strip()]
    scanner = Scanner(
        target,
        verbose=args.verbose,
        follow_symlinks=args.follow_symlinks,
        max_size=args.max_size,
        excludes=excludes,
        allowlist_path=args.allowlist,
        aggressive=args.aggressive,
    )
    results = scanner.scan()

    # Filter by min-score and types
    filtered = {}
    for file, issues in results.items():
        out_issues = []
        for i in issues:
            if i.get("score", 0) < args.min_score:
                continue
            if types and i.get("type") not in types:
                continue
            out_issues.append(i)
        if out_issues:
            filtered[file] = out_issues

    if args.save_report:
        open(args.save_report, "w", encoding="utf-8").write(dump_results_json(filtered))

    if args.json:
        print(dump_results_json(filtered))
    else:
        if args.pretty:
            print_results_console(filtered, verbose=args.verbose)
        else:
            print(dump_results_console(filtered))

if __name__ == "__main__":
    main()
