from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich import box
import json

console = Console()

def severity_for(score: int):
    if score >= 9:
        return "CRITICAL", "bold red"
    if score >= 7:
        return "HIGH", "red"
    if score >= 5:
        return "MEDIUM", "yellow3"
    return "LOW", "green"

def print_results_console(results: dict, verbose: bool = False):
    total = sum(len(v) for v in results.values())
    if total == 0:
        console.print("[bold green]No high-confidence findings.[/bold green]")
        return

    high = sum(1 for issues in results.values() for i in issues if i.get("score",0) >= 7)
    console.print(Panel(f"[bold]{total} findings[/bold] • [red]{high} high/critical[/red]", title="Scan Summary"))

    table = Table(box=box.SIMPLE_HEAVY, title="Config Security Checker Results", show_lines=False)
    table.add_column("File", overflow="fold", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Detail", overflow="fold")
    table.add_column("Score", justify="right")

    for file, issues in sorted(results.items()):
        for issue in issues:
            t = issue.get("type", "")
            score = int(issue.get("score", 0))
            sev_label, sev_color = severity_for(score)
            sev = Text(sev_label, style=sev_color)
            detail = ""
            if t == "secret":
                detail = f"{issue.get('rule')} @ line {issue.get('line')}: {issue.get('match')}"
                if issue.get("note"):
                    detail += f" ({issue.get('note')})"
            elif t == "weak-cipher":
                detail = f"{issue.get('cipher')} (token {issue.get('token')})"
            elif t == "pem":
                detail = issue.get("header", "")
                if "rsa_bits" in issue:
                    detail += f" - rsa {issue['rsa_bits']} bits"
            table.add_row(file, t, sev, detail, str(score))
    console.print(table)

    counts = {}
    for issues in results.values():
        for i in issues:
            counts[i.get("type")] = counts.get(i.get("type"), 0) + 1
    parts = [f"{k}: {v}" for k, v in counts.items()]
    console.print(Panel(", ".join(parts), title="Counts by Type"))

def dump_results_console(results: dict) -> str:
    lines = []
    for file, issues in results.items():
        lines.append(f"== {file} ==")
        for i in issues:
            lines.append(str(i))
    return "\n".join(lines)
