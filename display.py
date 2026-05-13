from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich         import box
from rich.text    import Text

from parser  import parse_email, EmailHeaders
from checker import check_spf, check_dkim
from dmarc   import check_dmarc
from scorer  import compute_score, RiskScore

console = Console() # creating a 

def display_report(filepath):
    h = parse_email(filepath)

    with open(filepath, "rb") as f:
        raw = f.read()

    spf   = check_spf(h.return_path_domain or h.from_domain or "", h.originating_ip or "")
    dkim  = check_dkim(raw)
    dmarc = check_dmarc(
        from_domain = h.from_domain,
        spf_domain  = h.return_path_domain,
        spf_passed  = spf.result.value == "pass",
        dkim_domain = dkim.signing_domain,
        dkim_passed = dkim.result.value == "pass",
    )
    score = compute_score(h, spf, dkim, dmarc)

    console.print()
    console.rule(f"[bold cyan]Email Analysis — {filepath}[/bold cyan]")

    # Basic information (1st table)
    t = Table(box=box.SIMPLE, padding=(0,2))
    t.add_column("Field Name")
    t.add_column("Value")
    t.add_row("From",       h.from_address or "[dim]—[/dim]")
    t.add_row("Subject",    f"[bold]{h.subject}[/bold]" if h.subject else "[dim]—[/dim]")
    t.add_row("Date",       h.date or "[dim]—[/dim]")
    t.add_row("Message-ID", h.message_id or "[dim]—[/dim]")
    console.print(Panel(t, title="[bold]Basic Information[/bold]", border_style="violet"))

    def d(x): 
        return f"[blue]{x}[/blue]" if x else "[dim]—[/dim]"
    
    # Sender chain (2nd table)
    t2 = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    t2.add_column("F")
    t2.add_column("V")
    t2.add_column("Domain", style="blue")
    
    t2.add_row("From address",   h.from_address  or "[dim]—[/dim]", d(h.from_domain))
    t2.add_row("Return-Path",    h.return_path   or "[dim]—[/dim]", d(h.return_path_domain))
    t2.add_row("Reply-To",       h.reply_to      or "[dim]—[/dim]", d(h.reply_to_domain))
    t2.add_row("Originating IP", h.originating_ip or "[dim]—[/dim]", "")
    console.print(Panel(t2, title="[bold]Sender Chain[/bold]", border_style="violet"))

    # Auth checks (3rd table)
    def result_color(val):
        v = val.lower()
        if v == "pass":   return f"[green]{val.upper()}[/green]"
        if v in ("fail","permerror"): return f"[red]{val.upper()}[/red]"
        return f"[yellow]{val.upper()}[/yellow]"

    t3 = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    t3.add_column("Check", style="dim", width=10)
    t3.add_column("Result", width=14)
    t3.add_column("Detail")
    t3.add_row("SPF",   result_color(spf.result.value),   spf.reason)
    t3.add_row("DKIM",  result_color(dkim.result.value),  dkim.reason)
    t3.add_row("DMARC", result_color(dmarc.result.value), dmarc.reason)
    t3.add_row("",      "",                               f"[dim]Policy: {dmarc.policy.value}[/dim]")
    console.print(Panel(t3, title="[bold]Authentication Results[/bold]", border_style="blue"))

    if h.flags:
        lines = "\n".join(f"  [yellow]🚩[/yellow]  [yellow]{f}[/yellow]" for f in h.flags)
        console.print(Panel(lines, title="[bold]Header Flags[/bold]", border_style="yellow"))
    else:
        console.print(Panel("[green]No suspicious header patterns detected.[/green]",
                            title="[bold]Header Flags[/bold]", border_style="green"))

    color = {"green": "green", "yellow": "yellow", "red": "red"}.get(score.color, "white")

    bar_filled = round(score.score / 5)   # 20 chars = full bar
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    score_lines = [
        f"  [{color}]{bar}[/{color}]  [{color}]{score.score}/100[/{color}]",
        f"  Prediction: [{color}][bold]{score.verdict}[/bold][/{color}]",
        ""
    ]
    if score.details:
        score_lines.append("  Deductions:")
        for d in score.details:
            if d.deduction > 0:
                score_lines.append(
                    f"    [red]-{d.deduction:2d}[/red]  [{d.category}] {d.label}"
                )
        score_lines.append(f"\n  [dim]Total deducted: {score.total_deducted} pts[/dim]")

    border = color if color in ("green","yellow","red") else "white"
    console.print(Panel("\n".join(score_lines),
                        title="[bold]Trust Score[/bold]", border_style=border))
    console.print()


if __name__ == "__main__":
    import sys
    files = sys.argv[1:] if len(sys.argv) > 1 else [
        "samples/legitimate.eml",
        "samples/spoofed.eml",
    ]
    for path in files:
        try:
            display_report(path)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")