#!/usr/bin/env python3
"""Deterministic orchestrator for the mobile-analysis-skill pipeline.

The LLM still spawns the specialist/prosecutor/skeptic subagents (only a live
harness can do that), but this script owns everything that can be made
deterministic and is currently left to the orchestrating model's memory:

* ``status``        — print the pipeline state of an engagement;
* ``dedup``         — merge candidate findings that share a fingerprint;
* ``under-review``  — flip ``candidate`` -> ``under-review`` atomically;
* ``next``          — print the deterministic queue of findings awaiting a verdict;
* ``decide``        — apply the severity-rating.md decision rule to the structured
                      verdicts the prosecutor/skeptics wrote, and write the result;
* ``consolidate``   — merge prosecutor case + skeptic verdicts + decision into the
                      canonical ``exploitation/<id>.md``;
* ``validate``      — check pipeline invariants.

This does not replace ``severity-rating.md``; it *encodes* its decision rule so
the orchestrating model no longer has to remember it. The only judgments that
remain with the agents are the ones that are genuinely judgment calls, and each
is recorded *structurally* (see "Structured verdicts" below) so this script can
aggregate them deterministically.

Structured verdicts (the contract ``decide`` reads)
---------------------------------------------------
Prosecutor writes ``exploitation/<id>.prosecutor.json``::

    {"finding_id": "AND-MAN-001", "proposed_severity": "high",
     "attacker_model": "physical", "static_unambiguous": false}

Each skeptic writes ``exploitation/<id>.skeptic-<label>.json``::

    {"finding_id": "AND-MAN-001", "label": "1",
     "verdict": "stands", "well_evidenced": true, "closes_path": null,
     "checked": ["re-read PayActivity.kt ...", "checked targetSdk 33 ..."],
     "reason": "no defeating fact found"}

``verdict`` is ``"refuted"`` or ``"stands"``. ``well_evidenced`` means the
verdict cites a specific fact (code line / platform default / control) that
genuinely breaks a step the prosecutor did not already address. ``closes_path``
is meaningful only for a well-evidenced ``refuted`` (does it fully close the
path, or only raise doubt?); it is ``null`` for ``stands``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_findings import fingerprint  # noqa: E402  (single source of truth)

TERMINAL = {"confirmed", "potential", "informational", "false-positive"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITIES = set(SEVERITY_RANK)


# --------------------------------------------------------------------------- #
# loading / saving
# --------------------------------------------------------------------------- #

def load_findings(engagement: Path) -> tuple[list[dict], list[str]]:
    """Return (records, warnings). A record is a dict from findings.jsonl."""
    source = engagement / "findings" / "findings.jsonl"
    records: list[dict] = []
    warnings: list[str] = []
    if not source.exists():
        warnings.append(f"{source} not found")
        return records, warnings
    for i, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            warnings.append(f"{source.name}:{i}: invalid JSON: {exc.msg}")
            continue
        records.append(rec)
    return records, warnings


def save_findings(engagement: Path, records: list[dict]) -> None:
    """Atomically rewrite findings.jsonl (temp file + rename)."""
    source = engagement / "findings" / "findings.jsonl"
    source.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(source.parent), prefix=".findings.", suffix=".tmp")
    with open(fd, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    Path(tmp).replace(source)


def prosecutor_json(engagement: Path, fid: str) -> Path:
    return engagement / "exploitation" / f"{fid}.prosecutor.json"


def prosecutor_md(engagement: Path, fid: str) -> Path:
    return engagement / "exploitation" / f"{fid}.md"


def skeptic_jsons(engagement: Path, fid: str) -> list[Path]:
    return sorted(engagement.glob(f"exploitation/{fid}.skeptic-*.json"))


def skeptic_mds(engagement: Path, fid: str) -> list[Path]:
    return sorted(engagement.glob(f"exploitation/{fid}.skeptic-*.md"))


def read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"warning: {path}: invalid JSON: {exc.msg}", file=sys.stderr)
        return None


def required_skeptics(severity: str | None) -> int:
    return 3 if severity in {"critical", "high"} else 2


# --------------------------------------------------------------------------- #
# panel progress
# --------------------------------------------------------------------------- #

def panel_progress(engagement: Path, rec: dict) -> dict:
    """Describe how far a finding has advanced through the panel."""
    fid = rec.get("finding_id", "?")
    sev = rec.get("severity_initial")
    return {
        "id": fid,
        "severity": sev,
        "prosecutor": prosecutor_json(engagement, fid).exists() or prosecutor_md(engagement, fid).exists(),
        "skeptics": len(skeptic_jsons(engagement, fid)),
        "required": required_skeptics(rec.get("final_severity") or sev),
    }


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_status(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    records, warnings = load_findings(engagement)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    counts: dict[str, int] = {}
    for r in records:
        s = r.get("status", "candidate")
        counts[s] = counts.get(s, 0) + 1

    print(f"engagement: {engagement.name}")
    print(f"findings:   {len(records)} record(s)")
    print()
    print("status          count")
    print("-------------  -----")
    for s in ["candidate", "under-review", "confirmed", "potential", "informational", "false-positive"]:
        print(f"{s:<13}  {counts.get(s, 0)}")
    print()

    queue = [r for r in records if r.get("status") in ("candidate", "under-review")]
    queue.sort(key=lambda r: (SEVERITY_RANK.get(r.get("severity_initial"), 99), r.get("finding_id", "")))
    if queue:
        print("panel queue (deterministic order):")
        for i, r in enumerate(queue, 1):
            p = panel_progress(engagement, r)
            print(f"  {i}. {p['id']:<14} {str(p['severity']):<8} prosecutor={'y' if p['prosecutor'] else 'n'} "
                  f"skeptics={p['skeptics']}/{p['required']}")
    else:
        print("panel queue: empty")
    print()

    done = [r for r in records if r.get("status") in TERMINAL]
    if done:
        print("terminal:")
        for r in done:
            p = panel_progress(engagement, r)
            print(f"  {p['id']:<14} {r.get('status')}/{r.get('final_severity')} "
                  f"skeptics={p['skeptics']}")
    return 0


def cmd_dedup(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    records, warnings = load_findings(engagement)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    groups: dict[tuple, list[dict]] = {}
    for r in records:
        if r.get("status") != "candidate":
            continue
        key = fingerprint(r)
        if not key[0] or not key[1] or not key[2]:
            continue
        groups.setdefault(key, []).append(r)

    merged = 0
    for key, group in groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda r: r.get("finding_id", ""))
        keep = group[0]
        for other in group[1:]:
            keep["ref_ids"] = sorted(set(keep.get("ref_ids", []) + other.get("ref_ids", [])))
            keep["evidence"] = keep.get("evidence", []) + other.get("evidence", [])
            if SEVERITY_RANK.get(other.get("severity_initial"), 99) < SEVERITY_RANK.get(keep.get("severity_initial"), 99):
                keep["severity_initial"] = other.get("severity_initial")
            note = f"merged {other.get('finding_id')} into {keep.get('finding_id')} (same fingerprint)"
            keep["notes"] = (keep.get("notes", "") + " " + note).strip()
            other["status"] = "informational"
            other["final_rating_reason"] = f"merged into {keep.get('finding_id')}"
            other["final_severity"] = keep.get("severity_initial")
            merged += 1

    if args.dry_run:
        print(f"[dry-run] would merge {merged} finding(s)")
        return 0

    save_findings(engagement, records)
    print(f"merged {merged} finding(s)")
    return 0


def cmd_under_review(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    records, warnings = load_findings(engagement)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    ids = args.ids
    if args.all:
        ids = [r.get("finding_id") for r in records if r.get("status") == "candidate"]
    if not ids:
        print("error: pass one or more finding ids, or --all", file=sys.stderr)
        return 2

    changed = 0
    for r in records:
        if r.get("finding_id") in ids:
            if r.get("status") == "candidate":
                r["status"] = "under-review"
                changed += 1
            elif r.get("status") == "under-review":
                pass
            else:
                print(f"warning: {r.get('finding_id')} is {r.get('status')}, skipping", file=sys.stderr)

    if args.dry_run:
        print(f"[dry-run] would set {changed} finding(s) to under-review")
        return 0

    save_findings(engagement, records)
    print(f"set {changed} finding(s) to under-review")
    return 0


def cmd_next(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    records, warnings = load_findings(engagement)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    queue = [r for r in records if r.get("status") in ("candidate", "under-review")]
    queue.sort(key=lambda r: (SEVERITY_RANK.get(r.get("severity_initial"), 99), r.get("finding_id", "")))

    if args.ids:
        for r in queue:
            print(r.get("finding_id"))
        return 0

    if not queue:
        print("(no findings awaiting a verdict)")
        return 0
    for i, r in enumerate(queue, 1):
        p = panel_progress(engagement, r)
        print(f"{i}. {p['id']}  [{p['severity']}]  prosecutor={'y' if p['prosecutor'] else 'n'}  "
              f"skeptics={p['skeptics']}/{p['required']}")
    return 0


def _claim(records: list[dict], reservations: list[dict], prefix: str, count: int, agent: str | None) -> tuple[list[str], dict]:
    """Compute the next `count` free IDs for a prefix, given findings + reservations."""
    used: set[int] = set()
    for r in records:
        fid = str(r.get("finding_id", ""))
        if fid.startswith(prefix + "-"):
            tail = fid.rsplit("-", 1)[-1]
            if tail.isdigit():
                used.add(int(tail))
    for res in reservations:
        for fid in res.get("ids", []):
            s = str(fid)
            if s.startswith(prefix + "-"):
                tail = s.rsplit("-", 1)[-1]
                if tail.isdigit():
                    used.add(int(tail))
    nxt = (max(used) + 1) if used else 1
    ids = [f"{prefix}-{nxt + i:03d}" for i in range(count)]
    return ids, {"prefix": prefix, "agent": agent, "ids": ids, "count": count}


def cmd_claim(args: argparse.Namespace) -> int:
    """Atomically reserve finding ids for a <PLATFORM>-<DOMAIN> prefix."""
    engagement = args.engagement.resolve()
    prefix = args.prefix.upper()
    if not re.match(r"^(AND|IOS|BOTH)-[A-Z0-9]{2,6}$", prefix):
        raise SystemExit(f"error: prefix must be <PLATFORM>-<DOMAIN>, e.g. AND-ADV or BOTH-OAU (got {prefix!r})")

    if fcntl is None:
        raise SystemExit("error: `claim` needs file locking (fcntl), unavailable on this platform")

    findings_dir = engagement / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    res_path = findings_dir / "reservations.jsonl"

    with open(findings_dir / ".id-alloc.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        records, warnings = load_findings(engagement)
        reservations: list[dict] = []
        if res_path.exists():
            for raw in res_path.read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                try:
                    reservations.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        ids, reservation = _claim(records, reservations, prefix, args.count, args.agent)
        with open(res_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(reservation) + "\n")

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    for i in ids:
        print(i)
    return 0


def _decide(records: list[dict], engagement: Path, fid: str, severity_override: str | None) -> tuple[dict, str]:
    """Apply the severity-rating.md decision rule. Returns (record, reason)."""
    rec = next((r for r in records if r.get("finding_id") == fid), None)
    if rec is None:
        raise SystemExit(f"error: finding {fid} not found in findings.jsonl")
    if rec.get("status") in TERMINAL:
        raise SystemExit(f"error: {fid} already terminal ({rec.get('status')})")

    prosecutor = read_json(prosecutor_json(engagement, fid)) or {}
    proposed = prosecutor.get("proposed_severity") or rec.get("severity_initial")
    gate = required_skeptics(proposed)

    verdicts = []
    for p in skeptic_jsons(engagement, fid):
        v = read_json(p)
        if v:
            v.setdefault("label", p.stem.rsplit("-", 1)[-1])
            verdicts.append(v)
    verdicts.sort(key=lambda v: v.get("label", ""))

    if not verdicts:
        raise SystemExit(f"error: no skeptic verdict files for {fid} (run the skeptics first)")

    n = len(verdicts)
    refuted_well = [v for v in verdicts if v.get("verdict") == "refuted" and v.get("well_evidenced")]
    stands_checked = [v for v in verdicts if v.get("verdict") == "stands" and v.get("checked")]
    all_refuted_unproven = (
        all(v.get("verdict") == "refuted" for v in verdicts)
        and not any(v.get("well_evidenced") for v in verdicts)
    )

    has_dynamic = any(e.get("type") == "dynamic" for e in rec.get("evidence", []))
    static_unambiguous = bool(prosecutor.get("static_unambiguous"))
    evidence_bar_met = has_dynamic or static_unambiguous

    final_severity = severity_override or proposed
    if final_severity not in SEVERITIES:
        raise SystemExit(f"error: invalid severity {final_severity!r}")

    if refuted_well:
        closing = next((v for v in refuted_well if v.get("closes_path")), None)
        if closing:
            status = "false-positive"
            reason = "well-evidenced refutation closed the path: " + (closing.get("reason") or "(no detail)")
        else:
            status = "potential"
            reason = "well-evidenced refutation raised doubt without fully closing the path"
    elif all_refuted_unproven:
        status = "potential"
        reason = "all skeptics refuted but none was well-evidenced"
    elif stands_checked and evidence_bar_met:
        if gate == 3 and n < 3:
            status = "potential"
            reason = f"critical/high needs 3 skeptic passes; only {n} present"
        else:
            status = "confirmed"
            reason = f"{len(stands_checked)}/{n} skeptic(s) stands with specific checks, evidence bar met, no well-evidenced refutation"
    else:
        status = "potential"
        if not evidence_bar_met:
            reason = "evidence bar not met (no dynamic evidence and static proof not marked unambiguous)"
        else:
            reason = "no skeptic returned a stands verdict with specific checks"

    rec["status"] = status
    rec["final_severity"] = final_severity
    rec["final_rating_reason"] = reason
    return rec, reason


def cmd_decide(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    records, warnings = load_findings(engagement)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    fid = args.finding_id
    rec, reason = _decide(records, engagement, fid, args.severity)

    print(f"{fid}: {rec['status']} / {rec['final_severity']}")
    print(f"  reason: {reason}")

    if args.dry_run:
        print("  [dry-run] no write")
        return 0

    save_findings(engagement, records)
    print("  wrote status / final_severity / final_rating_reason")
    return 0


def cmd_consolidate(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    fid = args.finding_id

    pmd = prosecutor_md(engagement, fid)
    if not pmd.exists():
        raise SystemExit(f"error: {pmd} not found (prosecutor has not written its case)")

    parts = [pmd.read_text(encoding="utf-8").rstrip()]
    for smd in skeptic_mds(engagement, fid):
        parts.append(smd.read_text(encoding="utf-8").rstrip())

    records, warnings = load_findings(engagement)
    rec = next((r for r in records if r.get("finding_id") == fid), None)
    if rec and rec.get("status") in TERMINAL:
        decision = (
            f"\n\n## Orchestrator decision\n"
            f"**Status:** {rec.get('status')}\n\n"
            f"**Final severity:** {rec.get('final_severity')}\n\n"
            f"**Reason:** {rec.get('final_rating_reason') or ''}\n"
        )
        parts.append(decision)

    out = "\n\n---\n\n".join(parts).rstrip() + "\n"

    if args.dry_run:
        print(f"[dry-run] would write {pmd} ({len(out)} bytes)")
        return 0

    pmd.write_text(out, encoding="utf-8")
    print(f"wrote consolidated transcript to {pmd}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    engagement = args.engagement.resolve()
    records, warnings = load_findings(engagement)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    seen: set[str] = set()
    problems = 0
    for r in records:
        fid = r.get("finding_id", "?")
        status = r.get("status")
        if fid in seen:
            print(f"error: duplicate finding_id {fid}")
            problems += 1
        seen.add(fid)

        if status in TERMINAL and status != "informational":
            if not (prosecutor_json(engagement, fid).exists() or prosecutor_md(engagement, fid).exists()):
                print(f"warning: {fid} is {status} but has no prosecutor transcript")
                problems += 1
            if status == "confirmed":
                sev = r.get("final_severity") or r.get("severity_initial")
                need = required_skeptics(sev)
                got = len(skeptic_jsons(engagement, fid))
                if got < need:
                    print(f"warning: {fid} confirmed with {got} skeptic(s), expected {need}")
                    problems += 1
                has_dynamic = any(e.get("type") == "dynamic" for e in r.get("evidence", []))
                has_justified_static = any(
                    e.get("type") == "static" and str(e.get("notes", "")).strip()
                    for e in r.get("evidence", [])
                )
                if not (has_dynamic or has_justified_static):
                    print(f"warning: {fid} confirmed without dynamic evidence or a static justification")
                    problems += 1
        if status == "candidate":
            print(f"note: {fid} still candidate (not yet handed to the panel)")
    print(f"checked {len(records)} record(s); {problems} problem(s)")
    return 0 if problems == 0 else 1


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

SELF_TESTS = [
    # (name, proposed_severity, static_unambiguous, has_dynamic, verdicts, expected_status)
    ("2/2 stands + dynamic -> confirmed (medium needs 2)",
     "medium", False, True,
     [{"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["x"]},
      {"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["y"]}],
     "confirmed"),
    ("2/2 stands + no dynamic + static ambiguous -> potential",
     "medium", False, False,
     [{"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["x"]},
      {"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["y"]}],
     "potential"),
    ("static marked unambiguous + 2 stands -> confirmed",
     "medium", True, False,
     [{"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["x"]},
      {"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["y"]}],
     "confirmed"),
    ("well-evidenced refuted that closes path -> false-positive",
     "medium", False, True,
     [{"verdict": "refuted", "well_evidenced": True, "closes_path": True, "reason": "sanitizer is exact-match"},
      {"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["x"]}],
     "false-positive"),
    ("well-evidenced refuted that only raises doubt -> potential",
     "medium", False, True,
     [{"verdict": "refuted", "well_evidenced": True, "closes_path": False, "reason": "precondition unverified"},
      {"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["x"]}],
     "potential"),
    ("high with only 2 stands -> potential (needs 3rd)",
     "high", False, True,
     [{"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["x"]},
      {"verdict": "stands", "well_evidenced": True, "closes_path": None, "checked": ["y"]}],
     "potential"),
    ("all refuted but none well-evidenced -> potential",
     "medium", False, True,
     [{"verdict": "refuted", "well_evidenced": False, "closes_path": None, "reason": "vague"},
      {"verdict": "refuted", "well_evidenced": False, "closes_path": None, "reason": "vague"}],
     "potential"),
]


def run_self_test() -> int:
    failures = 0
    for name, sev, static_unamb, has_dynamic, verdicts, expected in SELF_TESTS:
        with tempfile.TemporaryDirectory() as tmp:
            eng = Path(tmp) / "engagement-selftest"
            (eng / "findings").mkdir(parents=True)
            (eng / "exploitation").mkdir(parents=True)
            fid = "AND-TST-001"
            rec = {
                "finding_id": fid, "status": "under-review", "severity_initial": sev,
                "evidence": [{"type": "dynamic"}] if has_dynamic else [{"type": "static", "notes": ""}],
            }
            (eng / "findings" / "findings.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
            (eng / "exploitation" / f"{fid}.prosecutor.json").write_text(
                json.dumps({"proposed_severity": sev, "static_unambiguous": static_unamb}), encoding="utf-8")
            for i, v in enumerate(verdicts, 1):
                v = dict(v, finding_id=fid, label=str(i))
                (eng / "exploitation" / f"{fid}.skeptic-{i}.json").write_text(
                    json.dumps(v), encoding="utf-8")
            records, _ = load_findings(eng)
            rec_out, _ = _decide(records, eng, fid, None)
            ok = rec_out["status"] == expected
            print(f"self-test [{'ok' if ok else 'FAIL'}] {name}: got {rec_out['status']}, expected {expected}")
            if not ok:
                failures += 1

    # claim self-test
    recs = [{"finding_id": "AND-ADV-001"}, {"finding_id": "AND-ADV-002"}]
    resvs = [{"ids": ["AND-ADV-003"]}]
    ids, _ = _claim(recs, resvs, "AND-ADV", 2, "network-backend-auditor")
    expected_ids = ["AND-ADV-004", "AND-ADV-005"]
    ok = ids == expected_ids
    print(f"self-test [{'ok' if ok else 'FAIL'}] claim next-free (skips findings + reservations): got {ids}, expected {expected_ids}")
    if not ok:
        failures += 1

    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command")

    def engagement_arg(sp):
        sp.add_argument("engagement", type=Path, help="engagement-<slug>/ directory")

    sp = sub.add_parser("status", help="pipeline state of an engagement")
    engagement_arg(sp)
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("dedup", help="merge candidate findings that share a fingerprint")
    engagement_arg(sp)
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_dedup)

    sp = sub.add_parser("under-review", help="flip candidate -> under-review")
    engagement_arg(sp)
    sp.add_argument("ids", nargs="*", help="finding ids to mark (or use --all)")
    sp.add_argument("--all", action="store_true", help="mark every candidate")
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_under_review)

    sp = sub.add_parser("next", help="deterministic queue of findings awaiting a verdict")
    engagement_arg(sp)
    sp.add_argument("--ids", action="store_true", help="print only finding ids")
    sp.set_defaults(func=cmd_next)

    sp = sub.add_parser("claim", help="atomically reserve finding ids for a <PLATFORM>-<DOMAIN> prefix")
    engagement_arg(sp)
    sp.add_argument("prefix", help="prefix like AND-ADV or BOTH-OAU")
    sp.add_argument("--count", type=int, default=1, help="number of ids to reserve (default 1)")
    sp.add_argument("--agent", help="agent name to record against the reservation")
    sp.set_defaults(func=cmd_claim)

    sp = sub.add_parser("decide", help="apply the decision rule and write status/severity")
    engagement_arg(sp)
    sp.add_argument("finding_id", help="finding id to decide")
    sp.add_argument("--severity", help="override final_severity (default: prosecutor's proposed_severity)")
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_decide)

    sp = sub.add_parser("consolidate", help="merge prosecutor + skeptic transcripts + decision")
    engagement_arg(sp)
    sp.add_argument("finding_id")
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_consolidate)

    sp = sub.add_parser("validate", help="check pipeline invariants")
    engagement_arg(sp)
    sp.set_defaults(func=cmd_validate)

    p.add_argument("--self-test", action="store_true", help="run the decision-rule self-tests")
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
