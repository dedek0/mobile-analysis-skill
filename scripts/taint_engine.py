#!/usr/bin/env python3
"""Deterministic taint pre-pass: run Semgrep (and FlowDroid when available) over a
decompiled target, normalize the results into structured taint traces, and write
them where the taint-flow-analyst can consume them.

This does not replace the taint-flow-analyst: the engines prove *mechanical*
dataflow (does this source actually reach this sink?), and the agent adds
*judgment* (sanitizer adequacy, reachability by the stated attacker model, real
finding vs platform behavior). It exists to cut the false negatives an LLM
produces when reading decompiled code by eye, and to make flow-finding
reproducible. Each trace is emitted as a JSON line in findings/taint.jsonl and
can be cited in a finding's ``evidence`` exactly like a static reference.

Commands:
  check        report which engines are available and how they would be invoked
  scan         run the available engines and write findings/taint.jsonl + report
  --self-test  validate the normalizers against sample engine output

Engines:
  Semgrep   — taint rules in rules/semgrep/mobile-taint.yaml (needs `semgrep` on PATH)
  FlowDroid — needs a FlowDroid CLI: either a `flowdroid` binary, or the
              `FLOWDROID_JAR` env var pointing at soot-infoflow-cmd jar, plus
              `ANDROID_PLATFORMS` pointing at a directory of android.jar files.
              See rules/flowdroid/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEMGREP_RULES = REPO_ROOT / "rules" / "semgrep" / "mobile-taint.yaml"
FLOWDROID_SS = REPO_ROOT / "rules" / "flowdroid" / "SourcesAndSinks.txt"

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Fallback mapping rule_id -> metadata, used when PyYAML is unavailable.
# Keep in sync with rules/semgrep/mobile-taint.yaml.
RULE_META_FALLBACK = {
    "android.taint.intent-to-webview": {"ref_id": "TNT-01", "platform": "android"},
    "android.taint.intent-to-exec": {"ref_id": "TNT-01", "platform": "android"},
    "android.taint.intent-to-sql": {"ref_id": "TNT-03", "platform": "android"},
    "android.taint.intent-to-file": {"ref_id": "TNT-05", "platform": "android"},
    "android.taint.intent-redispatch": {"ref_id": "TNT-02", "platform": "android"},
    "ios.taint.url-to-wkwebview": {"ref_id": "TNT-01", "platform": "ios"},
    "ios.taint.pasteboard-to-sink": {"ref_id": "TNT-07", "platform": "ios"},
    "js.taint.linking-to-eval": {"ref_id": "TNT-01", "platform": "android"},
}

# Sink substrings -> taint-analysis.md ref id, for FlowDroid signature mapping.
FLOWDROID_SINK_REFS = [
    ("loadUrl", "TNT-01"),
    ("loadData", "TNT-01"),
    ("rawQuery", "TNT-03"),
    ("execSQL", "TNT-03"),
    ("exec(", "TNT-01"),
    ("File: void <init>", "TNT-05"),
    ("startActivity", "TNT-02"),
]

# Hermes bytecode magic (first 4 bytes of a *.hbc / index.android.bundle).
HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

# Deterministic pattern extractor for decompiled Hermes JS. hermes-dec emits
# register-based pseudo-JS (`r0 = fn.bind(...)(args)`) that is parseable but not
# friendly to taint rules, so these patterns pull out the security-relevant
# *sightings* (endpoints, auth, storage keys, SSRF payloads, secrets) that the
# taint-flow-analyst / business-logic-auditor then reason about.
# (category, compiled regex, message, ref_id)
HERMES_PATTERNS = [
    ("ssrf-payload", re.compile(r"""['"](/latest/meta-data[^'"]*|/internal/(?:secret|config[^'"]*))['"]"""),
     "Cloud metadata / internal endpoint payload referenced in JS (SSRF)", None),
    ("endpoint", re.compile(r"""['"](/api/[^'"]+|/admin/[^'"]*|/login|/transfer|/profile[^'"]*|/upload_profile_picture[^'"]*)['"]"""),
     "API endpoint referenced from the JS client", None),
    ("auth", re.compile(r"""['"]?(Authorization|Bearer)['"]?"""),
     "Authorization header / Bearer token usage", None),
    ("sensitive-storage", re.compile(r"""['"](jwt_token|is_admin|account_number|password|api_key|apikey)['"]"""),
     "Sensitive key stored/handled client-side", None),
    ("dynamic-code", re.compile(r"\b(eval|new Function)\s*\("),
     "Dynamic code execution sink", "TNT-01"),
    ("hardcoded-secret", re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|sk_(?:test|live)_[A-Za-z0-9]+)"),
     "Hardcoded secret in JS", "ADV-84"),
]


def which(name: str) -> str | None:
    return shutil.which(name)


def load_rule_meta() -> dict[str, dict]:
    if yaml is not None and SEMGREP_RULES.exists():
        try:
            doc = yaml.safe_load(SEMGREP_RULES.read_text(encoding="utf-8"))
            return {
                r["id"]: {
                    "ref_id": (r.get("metadata") or {}).get("ref_id"),
                    "platform": (r.get("metadata") or {}).get("platform"),
                }
                for r in doc.get("rules", [])
            }
        except Exception:
            pass
    return RULE_META_FALLBACK


# --------------------------------------------------------------------------- #
# normalizers (each returns a dict trace, or None)
# --------------------------------------------------------------------------- #

def _loc(loc: dict | None) -> str | None:
    if not loc:
        return None
    path = loc.get("path")
    line = (loc.get("start") or {}).get("line")
    if not path:
        return None
    return f"{path}:{line}" if line else path


def _trace_content(part: dict | None) -> str | None:
    if not part:
        return None
    return part.get("content")


def normalize_semgrep(result: dict, index: int, rule_meta: dict) -> dict | None:
    """Turn one Semgrep --json finding into a taint trace."""
    check_id = result.get("check_id", "")
    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}

    # Semgrep namespaces the rule id with the config path (e.g. "rules.semgrep.").
    rule_id = check_id
    for prefix in ("rules.semgrep.", "rules.", "semgrep."):
        if rule_id.startswith(prefix):
            rule_id = rule_id[len(prefix):]
            break

    ref_id = meta.get("ref_id") or rule_meta.get(check_id, {}).get("ref_id") or rule_meta.get(rule_id, {}).get("ref_id")
    platform = meta.get("platform") or rule_meta.get(check_id, {}).get("platform") or rule_meta.get(rule_id, {}).get("platform")

    # Source/sink come from the dataflow trace when Semgrep emits one (non-local
    # flows). For local flows the finding's own location *is* the sink.
    dt = extra.get("dataflow_trace") or {}
    source_part = dt.get("source") or {}
    sink_part = dt.get("sink") or {}
    source = _trace_content(source_part)
    sink = _trace_content(sink_part)
    source_location = _loc(source_part.get("location"))
    sink_location = _loc(sink_part.get("location"))

    path = result.get("path")
    start_line = (result.get("start") or {}).get("line")
    if not sink_location and path:
        sink_location = f"{path}:{start_line}" if start_line else path

    return {
        "id": f"TAINT-{index:04d}",
        "engine": "semgrep",
        "rule_id": rule_id,
        "ref_id": ref_id,
        "platform": platform,
        "severity": extra.get("severity") or result.get("severity"),
        "message": (extra.get("message") or "").strip(),
        "source": source,
        "sink": sink,
        "source_location": source_location,
        "sink_location": sink_location,
    }


def map_flowdroid_ref(sink_sig: str) -> str | None:
    for needle, ref in FLOWDROID_SINK_REFS:
        if needle in sink_sig:
            return ref
    return None


def normalize_flowdroid(raw_line: str, index: int) -> dict | None:
    """Turn one FlowDroid 'Found a flow to sink ...' line into a taint trace."""
    if "Found a flow to sink" not in raw_line:
        return None
    sink = None
    m = re.search(r"to sink\s+(.*?)\s+from source\s+(.*)$", raw_line)
    if m:
        sink = m.group(1).strip().rstrip(",")
        source = m.group(2).strip().rstrip(":").strip()
    else:
        sink = raw_line.strip()
        source = None
    return {
        "id": f"TAINT-{index:04d}",
        "engine": "flowdroid",
        "rule_id": None,
        "ref_id": map_flowdroid_ref(sink or ""),
        "platform": "android",
        "severity": None,
        "message": raw_line.strip(),
        "source": source,
        "sink": sink,
        "source_location": None,
        "sink_location": None,
    }


# --------------------------------------------------------------------------- #
# Hermes (React Native) JS
# --------------------------------------------------------------------------- #

def decompile_hermes(bundle: Path, out_path: Path) -> Path | None:
    """Decompile a Hermes bundle with hbc-decompiler (hermes-dec). Returns the JS path or None."""
    binp = which("hbc-decompiler")
    if not binp:
        return None
    out_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([binp, str(bundle), str(out_path)], capture_output=True, text=True)
    if out_path.exists() and out_path.stat().st_size > 0:
        return out_path
    detail = (proc.stderr or proc.stdout or "").strip()[:200]
    print(f"warning: Hermes decompile failed: {detail}", file=sys.stderr)
    return None


def is_hermes_bundle(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == HERMES_MAGIC
    except OSError:
        return False


def _hermes_js_scan(js_path: Path) -> list[dict]:
    """Deterministic security-relevant pattern scan over decompiled Hermes JS."""
    traces: list[dict] = []
    seen: set[tuple[str, str]] = set()
    try:
        lines = js_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return traces
    for lineno, line in enumerate(lines, 1):
        for category, pattern, msg, ref in HERMES_PATTERNS:
            for m in pattern.finditer(line):
                matched = m.group(0)
                key = (category, matched)
                if key in seen:
                    continue
                seen.add(key)
                traces.append({
                    "id": f"TAINT-H{len(traces) + 1:03d}",
                    "engine": "hermes-js",
                    "rule_id": f"hermes.{category}",
                    "ref_id": ref,
                    "platform": "android",
                    "severity": None,
                    "message": msg,
                    "source": None,
                    "sink": matched[:200],
                    "source_location": None,
                    "sink_location": f"{js_path.name}:{lineno}",
                })
    return traces


# --------------------------------------------------------------------------- #
# engines
# --------------------------------------------------------------------------- #

def run_semgrep(target: Path) -> list[dict]:
    if not which("semgrep"):
        return []
    if not SEMGREP_RULES.exists():
        print(f"warning: semgrep rules not found at {SEMGREP_RULES}", file=sys.stderr)
        return []
    cmd = [
        "semgrep", "scan",
        "--config", str(SEMGREP_RULES),
        "--json",
        "--dataflow-traces",
        "--no-git-ignore",
        "--quiet",
        str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        print(f"warning: could not parse semgrep output: {exc}", file=sys.stderr)
        return []
    return data.get("results", [])


def flowdroid_command() -> list[str] | None:
    """Return the FlowDroid command prefix, or None if it is not set up."""
    jar = os.environ.get("FLOWDROID_JAR")
    if jar and Path(jar).exists():
        return ["java", "-jar", jar]
    binp = which("flowdroid")
    if binp:
        return [binp]
    return None


def run_flowdroid(apk: Path) -> list[str]:
    cmd = flowdroid_command()
    if not cmd:
        return []
    platforms = os.environ.get("ANDROID_PLATFORMS")
    if not platforms:
        print("warning: FLOWDROID_JAR set but ANDROID_PLATFORMS not set; skipping FlowDroid", file=sys.stderr)
        return []
    full = cmd + ["-a", str(apk), "-p", platforms, "-s", str(FLOWDROID_SS)]
    proc = subprocess.run(full, capture_output=True, text=True)
    return (proc.stdout or "").splitlines()


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_check(args: argparse.Namespace) -> int:
    semgrep_ok = bool(which("semgrep"))
    fd_cmd = flowdroid_command()
    print("engine    available  notes")
    print("-------   ---------  -----")
    print(f"semgrep   {'yes' if semgrep_ok else 'no'}        rules: rules/semgrep/mobile-taint.yaml")
    if fd_cmd:
        note = f"invoked as: {' '.join(fd_cmd)}"
    else:
        note = "set FLOWDROID_JAR (or a `flowdroid` binary) + ANDROID_PLATFORMS"
    print(f"flowdroid {'yes' if fd_cmd else 'no'}        {note}")
    print(f"hermes    {'yes' if which('hbc-decompiler') else 'no'}        hbc-decompiler (hermes-dec) decompiles React Native bundles")
    print(f"jadx      {'yes' if which('jadx') else 'no'}        used to decompile an APK before scanning")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    target = args.target.resolve()
    engagement = args.engagement.resolve()
    findings_dir = engagement / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        raise SystemExit(f"error: target does not exist: {target}")

    engines = args.engines.split(",") if args.engines else ["semgrep", "flowdroid"]
    rule_meta = load_rule_meta()
    traces: list[dict] = []
    notes: list[str] = []

    if "semgrep" in engines:
        if which("semgrep"):
            results = run_semgrep(target)
            for i, res in enumerate(results, 1):
                t = normalize_semgrep(res, len(traces) + 1, rule_meta)
                if t:
                    traces.append(t)
            notes.append(f"semgrep: {len(results)} result(s)")
        else:
            notes.append("semgrep: not on PATH (skipped)")

    if "flowdroid" in engines:
        if args.apk and Path(args.apk).exists():
            lines = run_flowdroid(Path(args.apk))
            for raw in lines:
                t = normalize_flowdroid(raw, len(traces) + 1)
                if t:
                    traces.append(t)
            notes.append(f"flowdroid: {len([l for l in lines if 'Found a flow' in l])} flow line(s)")
        elif args.apk:
            notes.append(f"flowdroid: apk not found ({args.apk})")
        else:
            notes.append("flowdroid: no --apk given (skipped)")

    if args.hermes:
        hermes_path = Path(args.hermes)
        if not hermes_path.exists():
            notes.append(f"hermes: path not found ({args.hermes})")
        else:
            hermes_js: Path | None = None
            if is_hermes_bundle(hermes_path):
                out = engagement / "extracted" / "hermes" / (hermes_path.stem + ".decompiled.js")
                hermes_js = decompile_hermes(hermes_path, out)
                if hermes_js:
                    notes.append(f"hermes: decompiled {hermes_path.name} -> {hermes_js.name}")
                else:
                    notes.append("hermes: hbc-decompiler not available (skipped)")
            else:
                hermes_js = hermes_path
                notes.append(f"hermes: scanning decompiled JS {hermes_js.name}")
            if hermes_js:
                if which("semgrep"):
                    for res in run_semgrep(hermes_js):
                        t = normalize_semgrep(res, len(traces) + 1, rule_meta)
                        if t:
                            traces.append(t)
                ht = _hermes_js_scan(hermes_js)
                traces.extend(ht)
                notes.append(f"hermes: {len(ht)} JS sighting(s)")

    taint_jsonl = findings_dir / "taint.jsonl"
    with open(taint_jsonl, "w", encoding="utf-8") as fh:
        for t in traces:
            fh.write(json.dumps(t, ensure_ascii=False) + "\n")

    report = findings_dir / "taint-report.md"
    lines = ["# Taint engine report", ""]
    for n in notes:
        lines.append(f"- {n}")
    lines.append(f"\n{len(traces)} trace(s) written to `findings/taint.jsonl`.\n")
    if traces:
        lines.append("| id | engine | rule | ref | source | sink |")
        lines.append("|---|---|---|---|---|---|")
        for t in traces:
            src = (t.get("source") or "?")[:40]
            sink = (t.get("sink") or "?")[:40]
            lines.append(f"| {t['id']} | {t['engine']} | {t.get('rule_id') or '-'} | {t.get('ref_id') or '-'} | {src} | {sink} |")
        lines.append("")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {len(traces)} trace(s) to {taint_jsonl.relative_to(engagement.parent) if taint_jsonl.is_relative_to(engagement.parent) else taint_jsonl}")
    print(f"wrote {report.relative_to(engagement.parent) if report.is_relative_to(engagement.parent) else report}")
    for n in notes:
        print(f"  {n}")
    return 0


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

def run_self_test() -> int:
    failures = 0

    meta = {"android.taint.intent-to-webview": {"ref_id": "TNT-01", "platform": "android"}}
    finding_with_trace = {
        "check_id": "android.taint.intent-to-webview",
        "path": "com/example/WebActivity.java",
        "start": {"line": 42, "col": 1},
        "end": {"line": 57, "col": 10},
        "extra": {
            "message": "Intent-controlled data flows into WebView.loadUrl",
            "severity": "WARNING",
            "dataflow_trace": {
                "source": {"location": {"path": "com/example/WebActivity.java", "start": {"line": 42}}, "content": "getStringExtra(\"url\")"},
                "sink": {"location": {"path": "com/example/WebActivity.java", "start": {"line": 57}}, "content": "loadUrl(url)"},
            },
        },
    }
    t = normalize_semgrep(finding_with_trace, 1, meta)
    ok = (
        t
        and t["ref_id"] == "TNT-01"
        and t["source_location"] == "com/example/WebActivity.java:42"
        and t["sink_location"] == "com/example/WebActivity.java:57"
        and t["source"] == 'getStringExtra("url")'
        and t["sink"] == "loadUrl(url)"
    )
    print(f"self-test [{'ok' if ok else 'FAIL'}] semgrep normalize (with dataflow_trace): {t and (t['source_location'], t['sink_location'])}")
    if not ok:
        failures += 1

    finding_no_trace = {
        "check_id": "rules.semgrep.android.taint.intent-to-webview",
        "path": "com/example/WebActivity.java",
        "start": {"line": 57, "col": 1},
        "end": {"line": 57, "col": 10},
        "extra": {
            "message": "msg",
            "severity": "WARNING",
            "metadata": {"ref_id": "TNT-01", "platform": "android"},
        },
    }
    t = normalize_semgrep(finding_no_trace, 2, meta)
    ok = (
        t
        and t["rule_id"] == "android.taint.intent-to-webview"
        and t["ref_id"] == "TNT-01"
        and t["sink_location"] == "com/example/WebActivity.java:57"
        and t["source"] is None
    )
    print(f"self-test [{'ok' if ok else 'FAIL'}] semgrep normalize (local flow: metadata + sink location): rule={t and t['rule_id']} sink={t and t['sink_location']}")
    if not ok:
        failures += 1

    flow_line = "Found a flow to sink virtualinvoke $r1.<android.webkit.WebView: void loadUrl(java.lang.String)>($r2), from source $r2 = virtualinvoke $r0.<android.content.Intent: java.lang.String getStringExtra(java.lang.String)>(\"url\"):"
    t = normalize_flowdroid(flow_line, 1)
    ok = t and t["ref_id"] == "TNT-01" and "loadUrl" in (t["sink"] or "") and "getStringExtra" in (t["source"] or "")
    print(f"self-test [{'ok' if ok else 'FAIL'}] flowdroid normalize: ref={t and t['ref_id']} sink={t and t['sink']}")
    if not ok:
        failures += 1

    ok = map_flowdroid_ref("<android.database.sqlite.SQLiteDatabase: void execSQL(java.lang.String)>") == "TNT-03"
    print(f"self-test [{'ok' if ok else 'FAIL'}] flowdroid sink->ref mapping (execSQL -> TNT-03)")
    if not ok:
        failures += 1

    # hermes js pattern-scan self-test
    with tempfile.TemporaryDirectory() as tmp:
        js = Path(tmp) / "index.decompiled.js"
        js.write_text(
            "r4 = {'internalSecret': '/internal/secret', 'metadataRoot': '/latest/meta-data/'};\n"
            "r3 = 'Authorization'; r4 = 'Bearer ';\n"
            "r1 = ['jwt_token', 'is_admin'];\n"
            "r5 = '/admin/create_admin';\n",
            encoding="utf-8",
        )
        ht = _hermes_js_scan(js)
        cats = {t["rule_id"] for t in ht}
        ok = {"hermes.ssrf-payload", "hermes.auth", "hermes.sensitive-storage", "hermes.endpoint"} <= cats
        print(f"self-test [{'ok' if ok else 'FAIL'}] hermes js pattern scan: {sorted(cats)}")
        if not ok:
            failures += 1

    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("check", help="report which engines are available")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("scan", help="run the available engines and write taint.jsonl")
    sp.add_argument("target", type=Path, help="decompiled source directory (for semgrep)")
    sp.add_argument("engagement", type=Path, help="engagement-<slug>/ directory")
    sp.add_argument("--engines", help="comma-separated engines to run (default: semgrep,flowdroid)")
    sp.add_argument("--apk", help="APK/DEX path for FlowDroid")
    sp.add_argument("--hermes", help="Hermes bundle (assets/index.android.bundle) or an already-decompiled .js to scan")
    sp.set_defaults(func=cmd_scan)

    p.add_argument("--self-test", action="store_true", help="run the normalizer self-tests")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        return run_self_test()
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
