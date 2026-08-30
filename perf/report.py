#!/usr/bin/env python3
"""Turn a perf/run.sh results directory into tables and SVG charts.

    python3 perf/report.py reports/perf/<run> docs/perf

Writes <output>/data.md (every table) and <output>/img/*.svg. The narrative
report (docs/perf/performance-report.md) quotes and links them. Standard
library only.
"""

import json
import math
import sys
from collections import defaultdict
from pathlib import Path

# Chart chrome and categorical slots 1-3 of the validated reference palette
# (the first three validate all-pairs; slot 3 sits under 3:1 on the surface,
# so every line carries a direct label and every chart has a table).
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

SCENARIO_TITLES = {
    "profile": "GET /users/me",
    "sessions": "GET /users/me/sessions",
    "audit": "GET /users/me/audit",
    "two_factor": "GET /users/me/two-factor",
    "refresh": "POST /auth/refresh",
    "login": "POST /auth/login",
    "register": "POST /auth/register",
    "mixed": "Trafic mixte",
}

QUERY_TITLES = {
    "user_by_email": "Utilisateur par e-mail",
    "session_by_token": "Session par refresh token",
    "session_validation": "Validité d'une session",
    "active_sessions": "Sessions actives d'un compte",
    "failures_by_identifier": "Échecs récents par identifiant",
    "failures_by_ip": "Échecs récents par adresse",
    "consecutive_failures": "Échecs consécutifs d'un compte",
    "rbac": "Rôles et permissions",
    "audit_page": "Page d'historique (50)",
    "two_factor_overview": "Seconds facteurs et codes",
    "sign_in_write": "Écritures d'une connexion (tx)",
}


def load(run_dir):
    lines = [json.loads(l) for l in (run_dir / "results.jsonl").read_text().splitlines() if l.strip()]
    env_path = run_dir / "environment.json"
    env = json.loads(env_path.read_text()) if env_path.exists() else {}
    if not env.get("cpu_model"):
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            model = next((l.split(":", 1)[1].strip() for l in cpuinfo.read_text().splitlines()
                          if l.startswith("model name")), None)
            env["cpu_model"] = model
    return lines, env


def users_label(n):
    if n >= 1_000_000 and n % 1_000_000 == 0:
        return f"{n // 1_000_000}M"
    if n >= 1_000 and n % 1_000 == 0:
        return f"{n // 1_000}k"
    return str(n)


def num(v, digits=0):
    if v is None:
        return "-"
    if digits == 0:
        return f"{v:,.0f}".replace(",", " ")
    return f"{v:,.{digits}f}".replace(",", " ")


def ms(v):
    if v is None:
        return "-"
    if v < 1:
        return f"{v:.2f}"
    if v < 100:
        return f"{v:.1f}"
    return num(v)


def mb(b):
    return num((b or 0) / 1_048_576, 1 if (b or 0) < 10 * 1_048_576 else 0)


def setting_value(s):
    """pg_settings value in human units (memory settings come in kB or 8kB pages)."""
    unit, value = s.get("unit") or "", s["setting"]
    factor = {"kB": 1, "8kB": 8, "MB": 1024}.get(unit)
    if factor is None or not value.isdigit():
        return value + unit
    kib = int(value) * factor
    for size, suffix in ((1024 * 1024, "GB"), (1024, "MB")):
        if kib >= size and kib % size == 0:
            return f"{kib // size}{suffix}"
    return f"{kib}kB"


def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# SVG primitives -------------------------------------------------------------


def svg_open(width, height):
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family=\'{FONT}\'>',
        f'<rect width="{width}" height="{height}" fill="{SURFACE}"/>',
    ]


def text(x, y, content, size=11, fill=MUTED, anchor="start", weight="400"):
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" '
        f'text-anchor="{anchor}" font-weight="{weight}">{esc(content)}</text>'
    )


def legend(parts, x, y, names):
    cursor = x
    for i, name in enumerate(names):
        parts.append(
            f'<line x1="{cursor}" y1="{y - 4}" x2="{cursor + 18}" y2="{y - 4}" '
            f'stroke="{SERIES[i]}" stroke-width="2" stroke-linecap="round"/>'
        )
        parts.append(
            f'<circle cx="{cursor + 9}" cy="{y - 4}" r="4" fill="{SERIES[i]}" '
            f'stroke="{SURFACE}" stroke-width="2"/>'
        )
        parts.append(text(cursor + 24, y, name, 12, INK_2))
        cursor += 24 + 7.5 * len(name) + 22


def nice_ceiling(v):
    if v <= 0:
        return 1
    exp = 10 ** math.floor(math.log10(v))
    for step in (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if v <= step * exp:
            return step * exp
    return 10 * exp


def nice_step(raw):
    """Smallest 1, 2, 2.5 or 5 x 10^n at least `raw`."""
    if raw <= 0:
        return 1
    exp = 10 ** math.floor(math.log10(raw))
    for factor in (1, 2, 2.5, 5, 10):
        if raw <= factor * exp:
            return factor * exp
    return 10 * exp


def axis_number(v):
    if v >= 1000:
        return f"{v / 1000:g}k"
    return f"{v:g}"


def log_bounds(values):
    lo = min(v for v in values if v > 0)
    hi = max(values)
    return 10 ** math.floor(math.log10(lo)), 10 ** math.ceil(math.log10(hi))


def tick_label(v):
    if v >= 1000:
        return f"{v / 1000:g} s" if v % 1000 == 0 else f"{v:g}"
    return f"{v:g}"


def line_panel(parts, ox, oy, w, h, title, xlabels, series, log_y, unit):
    """series: [(name, [y or None per x])]. Draws into parts at (ox, oy)."""
    left, right, top, bottom = 48, 40, 26, 30
    pw, ph = w - left - right, h - top - bottom
    parts.append(text(ox, oy + 14, title, 12, INK, weight="600"))
    values = [v for _, ys in series for v in ys if v is not None and v > 0]
    if not values:
        return
    if log_y:
        lo, hi = log_bounds(values)
        ticks = [10 ** e for e in range(int(math.log10(lo)), int(math.log10(hi)) + 1)]
        def ypos(v):
            return oy + top + ph - (math.log10(v) - math.log10(lo)) / (math.log10(hi) - math.log10(lo)) * ph
    else:
        step = nice_step(max(values) / 4)
        hi = step * math.ceil(max(values) / step)
        ticks = [step * k for k in range(int(round(hi / step)) + 1)]
        def ypos(v):
            return oy + top + ph - v / hi * ph
    for t in ticks:
        y = ypos(t) if (not log_y or t > 0) else oy + top + ph
        parts.append(
            f'<line x1="{ox + left}" y1="{y:.1f}" x2="{ox + left + pw}" y2="{y:.1f}" '
            f'stroke="{GRID if t else AXIS}" stroke-width="1"/>'
        )
        label = tick_label(t) if log_y else axis_number(t)
        parts.append(text(ox + left - 6, y + 4, label, 10, MUTED, "end"))
    parts.append(
        f'<line x1="{ox + left}" y1="{oy + top + ph}" x2="{ox + left + pw}" y2="{oy + top + ph}" '
        f'stroke="{AXIS}" stroke-width="1"/>'
    )
    step = pw / max(1, len(xlabels) - 1)
    xpos = [ox + left + i * step for i in range(len(xlabels))]
    for x, label in zip(xpos, xlabels):
        parts.append(text(x, oy + top + ph + 16, label, 10, MUTED, "middle"))
    parts.append(text(ox + left + pw, oy + top + ph + 28, unit, 10, MUTED, "end"))

    ends = []
    for si, (name, ys) in enumerate(series):
        points = [(x, ypos(v)) for x, v in zip(xpos, ys) if v is not None and v > 0]
        if not points:
            continue
        path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(points))
        parts.append(
            f'<path d="{path}" fill="none" stroke="{SERIES[si]}" stroke-width="2" '
            f'stroke-linejoin="round" stroke-linecap="round"/>'
        )
        for x, y in points:
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{SERIES[si]}" '
                f'stroke="{SURFACE}" stroke-width="2"/>'
            )
        ends.append([points[-1][1], points[-1][0], name])
    # Direct labels at line ends, nudged apart.
    ends.sort()
    for i in range(1, len(ends)):
        if ends[i][0] - ends[i - 1][0] < 12:
            ends[i][0] = ends[i - 1][0] + 12
    for y, x, name in ends:
        parts.append(text(x + 8, y + 4, name, 10, INK_2))


def small_multiples(path, title, subtitle, panels, xlabels, series_names, log_y, unit, cols=4):
    pw, ph = 300, 200
    rows = math.ceil(len(panels) / cols)
    width, height = cols * pw + 24, rows * ph + 76
    parts = svg_open(width, height)
    parts.append(text(12, 22, title, 15, INK, weight="600"))
    parts.append(text(12, 40, subtitle, 12, INK_2))
    legend(parts, 12, 62, series_names)
    for i, (panel_title, series) in enumerate(panels):
        line_panel(
            parts, 12 + (i % cols) * pw, 72 + (i // cols) * ph, pw - 12, ph - 8,
            panel_title, xlabels, series, log_y, unit,
        )
    parts.append("</svg>")
    path.write_text("\n".join(parts))


def dot_plot(path, title, subtitle, rows, series_names, unit):
    """rows: [(label, [value or None per series])], log x axis."""
    label_w, width = 230, 900
    row_h, top = 26, 80
    height = top + len(rows) * row_h + 40
    parts = svg_open(width, height)
    parts.append(text(12, 22, title, 15, INK, weight="600"))
    parts.append(text(12, 40, subtitle, 12, INK_2))
    legend(parts, 12, 62, series_names)
    values = [v for _, vs in rows for v in vs if v]
    lo, hi = log_bounds(values)
    pl, pr = label_w, width - 40
    def xpos(v):
        return pl + (math.log10(v) - math.log10(lo)) / (math.log10(hi) - math.log10(lo)) * (pr - pl)
    e = int(math.log10(lo))
    while 10 ** e <= hi:
        x = xpos(10 ** e)
        parts.append(f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{top + len(rows) * row_h}" stroke="{GRID}" stroke-width="1"/>')
        parts.append(text(x, top + len(rows) * row_h + 16, tick_label(10 ** e), 10, MUTED, "middle"))
        e += 1
    parts.append(text(pr, top + len(rows) * row_h + 32, unit, 10, MUTED, "end"))
    for r, (label, vs) in enumerate(rows):
        y = top + r * row_h + row_h / 2
        parts.append(text(12, y + 4, label, 12, INK_2))
        present = [(xpos(v), si) for si, v in enumerate(vs) if v]
        if len(present) > 1:
            xs = [x for x, _ in present]
            parts.append(f'<line x1="{min(xs):.1f}" y1="{y:.1f}" x2="{max(xs):.1f}" y2="{y:.1f}" stroke="{AXIS}" stroke-width="2"/>')
        for x, si in present:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{SERIES[si]}" stroke="{SURFACE}" stroke-width="2"/>')
    parts.append("</svg>")
    path.write_text("\n".join(parts))


# Report ---------------------------------------------------------------------


def main():
    run_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    img = out_dir / "img"
    img.mkdir(parents=True, exist_ok=True)
    lines, env = load(run_dir)

    by_kind = defaultdict(list)
    for line in lines:
        by_kind[line["kind"]].append(line)
    volumes = sorted({l["users"] for l in lines if "users" in l})
    vnames = [users_label(v) for v in volumes][:3]
    volumes = volumes[:3]

    md = ["<!-- Generated by perf/report.py - do not edit by hand. -->", ""]

    # Environment and data set
    md += ["## Environnement de mesure", ""]
    md += ["| Élément | Valeur |", "|---|---|"]
    for key, label in [
        ("cpu_model", "Processeur"), ("cpus", "Cœurs"), ("memory_gb", "Mémoire (Go)"),
        ("kernel", "Noyau"), ("postgres", "PostgreSQL"), ("commit", "Commit mesuré"),
        ("cpu_groups", "Épinglage CPU"), ("api_db_pool", "Pool PostgreSQL de l'API"),
        ("argon2", "Argon2id"), ("duration_secs", "Mesure HTTP (s)"), ("warmup_secs", "Chauffe HTTP (s)"),
        ("db_duration_secs", "Mesure SQL (s)"),
    ]:
        if key in env:
            md.append(f"| {label} | {esc(env[key])} |")
    explains = {l["users"]: l for l in by_kind["explain"]}
    if explains:
        settings = next(iter(explains.values()))["settings"]
        md.append("| Réglages PostgreSQL | " + ", ".join(
            f"`{s['name']}={setting_value(s)}`" for s in settings) + " |")
    md.append("")

    seeds = {l["users"]: l for l in by_kind["seed"]}
    md += ["## Volumes de données", ""]
    relations_of_interest = ["users", "sessions", "login_attempts", "audit_log", "two_factor_methods", "recovery_codes"]
    header = "| Table | " + " | ".join(f"{n} : lignes | {n} : table / index (Mo)" for n in vnames) + " |"
    md += [header, "|---|" + "---:|---:|" * len(vnames)]
    for rel in relations_of_interest:
        row = [f"`{rel}`"]
        for v in volumes:
            e = explains.get(v)
            r = next((x for x in (e or {}).get("relations", []) if x["relation"] == rel), None)
            row.append(num(r["rows"]) if r else "-")
            row.append(f"{mb(r['table_bytes'])} / {mb(r['index_bytes'])}" if r else "-")
        md.append("| " + " | ".join(row) + " |")
    md.append("| **Base entière (Mo)** | " + " | ".join(
        (mb(explains[v]["database_bytes"]) if v in explains else "-") + " | " for v in volumes).rstrip(" |") + " | |")
    md.append("| Durée du peuplement (s) | " + " | ".join(
        (f"{seeds[v]['seconds']} (+{num(seeds[v]['added'])} comptes)" if v in seeds else "-") + " | " for v in volumes).rstrip(" |") + " | |")
    md.append("")

    # HTTP
    http = by_kind["http"]
    scenarios = [s for s in SCENARIO_TITLES if any(l["scenario"] == s for l in http)]
    levels = sorted({l["concurrency"] for l in http})
    idx = {(l["scenario"], l["users"], l["concurrency"]): l for l in http}

    if http:
        small_multiples(
            img / "http-throughput.svg",
            "Débit selon le nombre de clients simultanés",
            "Requêtes par seconde réussies ou non, une courbe par volume d'utilisateurs",
            [(SCENARIO_TITLES[s], [(n, [idx.get((s, v, c), {}).get("rps") for c in levels]) for n, v in zip(vnames, volumes)]) for s in scenarios],
            [str(c) for c in levels], vnames, False, "clients simultanés",
        )
        small_multiples(
            img / "http-p95.svg",
            "Latence p95 selon le nombre de clients simultanés",
            "Millisecondes, échelle logarithmique, une courbe par volume d'utilisateurs",
            [(SCENARIO_TITLES[s], [(n, [idx.get((s, v, c), {}).get("latency_ms", {}).get("p95") for c in levels]) for n, v in zip(vnames, volumes)]) for s in scenarios],
            [str(c) for c in levels], vnames, True, "clients simultanés",
        )
        md += ["## API HTTP", "", "![Débit](img/http-throughput.svg)", "", "![Latence p95](img/http-p95.svg)", ""]
        md += ["### Débit maximal par scénario", ""]
        md += ["| Scénario | " + " | ".join(f"{n} : req/s max (clients) | {n} : p95 à ce point (ms)" for n in vnames) + " |",
               "|---|" + "---:|---:|" * len(vnames)]
        for s in scenarios:
            row = [SCENARIO_TITLES[s]]
            for v in volumes:
                points = [idx[(s, v, c)] for c in levels if (s, v, c) in idx]
                if not points:
                    row += ["-", "-"]
                    continue
                best = max(points, key=lambda p: p["rps"])
                row += [f"{num(best['rps'])} ({best['concurrency']})", ms(best["latency_ms"]["p95"])]
            md.append("| " + " | ".join(row) + " |")
        md.append("")
        for s in scenarios:
            md += [f"### {SCENARIO_TITLES[s]}", ""]
            md += ["| Utilisateurs | Clients | req/s | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | Erreurs | CPU API (cœurs) | CPU PostgreSQL (cœurs) | CPU Redis+NATS | Commits PG/s | Hit ratio |",
                   "|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|"]
            for v in volumes:
                for c in levels:
                    l = idx.get((s, v, c))
                    if not l:
                        continue
                    errors = ", ".join(f"{k}×{num(n)}" for k, n in l["errors"].items()) or "0"
                    cpu = l.get("cpu", {})
                    db = l.get("db", {})
                    md.append("| " + " | ".join([
                        users_label(v), str(c), num(l["rps"]), ms(l["latency_ms"]["p50"]), ms(l["latency_ms"]["p95"]),
                        ms(l["latency_ms"]["p99"]), ms(l["latency_ms"]["max"]), errors,
                        num(cpu.get("api", {}).get("cores_busy"), 2), num(cpu.get("postgres", {}).get("cores_busy"), 2),
                        num(cpu.get("cache", {}).get("cores_busy"), 2), num(db.get("commits_per_sec")),
                        f"{db['cache_hit_ratio']:.4f}" if "cache_hit_ratio" in db else "-",
                    ]) + " |")
            if s == "mixed":
                md += ["", "Répartition par opération au plus fort volume et à la plus forte concurrence :", ""]
                top = idx.get((s, volumes[-1], levels[-1]))
                if top:
                    md += ["| Opération | req/s | p50 (ms) | p95 (ms) | p99 (ms) | Erreurs |", "|---|---:|---:|---:|---:|---|"]
                    for op, st in top["operations"].items():
                        md.append(f"| {op} | {num(st['rps'])} | {ms(st['latency_ms']['p50'])} | {ms(st['latency_ms']['p95'])} | {ms(st['latency_ms']['p99'])} | {', '.join(f'{k}×{n}' for k, n in st['errors'].items()) or '0'} |")
            md.append("")

    # Database
    db_lines = by_kind["db"]
    if db_lines:
        dlevels = sorted({l["concurrency"] for l in db_lines})
        didx = {(l["scenario"], l["users"], l["concurrency"]): l for l in db_lines}
        queries = [q for q in QUERY_TITLES if any(l["scenario"] == q for l in db_lines)]
        ref = 8 if 8 in dlevels else dlevels[len(dlevels) // 2]
        dot_plot(
            img / "db-p99.svg",
            f"Latence p99 des requêtes de l'application, {ref} connexions",
            "Millisecondes, échelle logarithmique, un point par volume d'utilisateurs",
            [(QUERY_TITLES[q], [didx.get((q, v, ref), {}).get("latency_ms", {}).get("p99") for v in volumes]) for q in queries],
            vnames, "ms",
        )
        small_multiples(
            img / "db-throughput.svg",
            "Débit des requêtes selon le nombre de connexions",
            "Requêtes par seconde par volume. Lectures : le générateur plafonne à 1 cœur dès 8 connexions, ces débits sont des minorants",
            [(QUERY_TITLES[q], [(n, [didx.get((q, v, c), {}).get("rps") for c in dlevels]) for n, v in zip(vnames, volumes)]) for q in queries],
            [str(c) for c in dlevels], vnames, False, "connexions", cols=4,
        )
        md += ["## Base de données", "", f"![Latence p99 des requêtes](img/db-p99.svg)", "", "![Débit des requêtes](img/db-throughput.svg)", ""]
        md += ["### Requêtes de l'application", ""]
        md += ["| Requête | Utilisateurs | " + " | ".join(f"{c} conn. : req/s | {c} conn. : p50 / p99 (ms)" for c in dlevels) + " | CPU PG à " + str(dlevels[-1]) + " conn. | Lectures disque/s |",
               "|---|---:|" + "---:|---:|" * len(dlevels) + "---:|---:|"]
        for q in queries:
            for v in volumes:
                row = [QUERY_TITLES[q], users_label(v)]
                for c in dlevels:
                    l = didx.get((q, v, c))
                    row += [num(l["rps"]), f"{ms(l['latency_ms']['p50'])} / {ms(l['latency_ms']['p99'])}"] if l else ["-", "-"]
                last = didx.get((q, v, dlevels[-1]), {})
                row.append(num(last.get("cpu", {}).get("postgres", {}).get("cores_busy"), 2))
                row.append(num(last.get("db", {}).get("blocks_read_per_sec")))
                md.append("| " + " | ".join(row) + " |")
        md.append("")

    # Plans
    if explains:
        md += ["### Plans d'exécution", "", "Médiane de 7 exécutions `EXPLAIN (ANALYZE, BUFFERS)` pour un compte au milieu de la plage.", ""]
        names = [p["query"] for p in explains[volumes[0]]["plans"]]
        md += ["| Requête | " + " | ".join(f"{n} : ms (blocs lus)" for n in vnames) + " | Plan au plus fort volume |",
               "|---|" + "---:|" * len(vnames) + "---|"]
        for name in names:
            row = [f"`{name}`"]
            last_plan = None
            for v in volumes:
                p = next((x for x in explains.get(v, {}).get("plans", []) if x["query"] == name), None)
                if p:
                    row.append(f"{ms(p['execution_ms_median'])} ({num(p['shared_read_blocks'] or 0)})")
                    last_plan = p
                else:
                    row.append("-")
            row.append(" → ".join(esc(n) for n in (last_plan or {}).get("nodes", [])) or "-")
            md.append("| " + " | ".join(row) + " |")
        md.append("")
        top_v = volumes[-1]
        md += [f"### Plus gros index à {users_label(top_v)} utilisateurs", "", "| Index | Table | Taille (Mo) | Parcours |", "|---|---|---:|---:|"]
        for ix in explains[top_v]["indexes"][:15]:
            md.append(f"| `{ix['index']}` | `{ix['relation']}` | {mb(ix['bytes'])} | {num(ix['scans'])} |")
        md.append("")

    statements = by_kind["statements"]
    if statements:
        for st in statements:
            md += [f"### `pg_stat_statements` à {users_label(st['users'])} utilisateurs ({esc(st['context'])})", ""]
            total = sum(x["total_ms"] for x in st["statements"]) or 1
            md += ["| Requête | Appels | Moyenne (ms) | Part du temps SQL | Blocs lus |", "|---|---:|---:|---:|---:|"]
            for x in st["statements"][:12]:
                query = esc(x["query"][:110]).replace("|", "\\|")
                md.append(f"| `{query}` | {num(x['calls'])} | {ms(x['mean_ms'])} | {x['total_ms'] / total:.1%} | {num(x['shared_read'])} |")
            md.append("")

    cleanups = by_kind["cleanup"]
    if cleanups:
        md += ["### Purge (lots de 5 000 lignes)", "", "| Tâche | " + " | ".join(f"{users_label(c['users'])} : lignes / ms par lot" for c in cleanups) + " |",
               "|---|" + "---:|" * len(cleanups) + ""]
        jobs = []
        for c in cleanups:
            for b in c["batches"]:
                if b["job"] not in jobs:
                    jobs.append(b["job"])
        for job in jobs:
            row = [f"`{job}`"]
            for c in cleanups:
                batches = [b for b in c["batches"] if b["job"] == job]
                row.append(", ".join(f"{num(b['deleted'])} / {ms(b['ms'])}" for b in batches))
            md.append("| " + " | ".join(row) + " |")
        md.append("")

    (out_dir / "data.md").write_text("\n".join(md))
    print(f"wrote {out_dir / 'data.md'} and {len(list(img.glob('*.svg')))} charts")


if __name__ == "__main__":
    main()
