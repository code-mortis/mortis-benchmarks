"""Offline pilot scoring. Truth is scorer-only; never mount these files in workers.

freeze writes an immutable protocol/code/corpus seal before live outputs exist.
blind produces a reviewer packet and a separate private arm key. score imports
independent semantic judgments; it never guesses a match from paths or rules.
All output files are create-only. No DB, provider requests or repository execution.
"""

import argparse
import hashlib
import json
import math
import random
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from prepare import MANIFEST, PILOT, ROOT, canonical, digest

PROTOCOL_PATH = ROOT / "scoring_protocol.json"
PROTOCOL = json.loads(PROTOCOL_PATH.read_text())
PROTOCOL_SHA256 = digest(canonical(PROTOCOL))
ARMS = PROTOCOL["arms"]
USAGE_FIELDS = ("requests", "tokens", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "reasoning_tokens", "cost_usd")
SEMANTIC_FIELDS = ("cause", "trigger", "consequence", "evidence")


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def load_corpus():
    manifest = json.loads(MANIFEST.read_text())
    content = {key: value for key, value in manifest.items() if key != "corpus_digest"}
    if digest(canonical(content)) != manifest["corpus_digest"]:
        raise ValueError("Corrupt frozen corpus manifest")
    cases = {}
    for record in manifest["cases"]:
        folder = PILOT / record["case_id"]
        source = json.loads((folder / "input.json").read_text())
        truth = json.loads((folder / "truth.json").read_text())
        for kind, value in (("input", source), ("truth", truth)):
            if digest(canonical(value)) != record["hashes"][kind]:
                raise ValueError(f"Frozen {kind} drift: {record['case_id']}")
        if digest((folder / "oracle.py").read_bytes()) != record["hashes"]["oracle"]:
            raise ValueError(f"Frozen oracle drift: {record['case_id']}")
        cases[record["case_id"]] = {**record, "source": source, "truth": truth}
    return manifest, cases


def freeze():
    manifest, _ = load_corpus()
    return {
        "schema": "mortis-engine-scoring-freeze/v1",
        "frozen_at": datetime.now(UTC).isoformat(),
        "protocol_sha256": PROTOCOL_SHA256,
        "scorer_sha256": digest(Path(__file__).read_bytes()),
        "corpus_digest": manifest["corpus_digest"],
        "corpus_manifest_sha256": digest(MANIFEST.read_bytes()),
        "profile_sha256": manifest["profile_sha256"],
        "protocol": PROTOCOL,
        "authorization": "No live requests authorized by this scoring seal",
    }


def key(attempt):
    return tuple(attempt[field] for field in ("case_id", "repetition", "graph", "cache"))


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def validate_results(results, manifest, cases):
    if results.get("schema") != "mortis-engine-eval-results/v1":
        raise ValueError("Unsupported results schema")
    if results.get("corpus_digest") != manifest["corpus_digest"] or results.get("protocol_sha256") != PROTOCOL_SHA256:
        raise ValueError("Results are not bound to the frozen corpus/protocol")
    # A partial run retains all planned arm/cases, including ones stopped before dispatch.
    planned = results.get("planned_attempts")
    if planned is None:
        planned = [
            {"case_id": case_id, "arm": arm, "repetition": 1, "graph": "off", "cache": "cold"}
            for case_id in cases for arm in ARMS
        ]
    schedule = {}
    for item in planned:
        identity = (*key(item), item["arm"])
        if item["case_id"] not in cases or item["arm"] not in ARMS or identity in schedule:
            raise ValueError("Unknown or duplicate planned arm/case")
        if not isinstance(item["repetition"], int) or isinstance(item["repetition"], bool) or item["repetition"] < 1:
            raise ValueError("Invalid repetition")
        if item["cache"] not in {"cold", "warm"} or item["graph"] not in {"off", "on"}:
            raise ValueError("Unknown cache/graph stratum")
        schedule[identity] = item
    if not schedule or any((*pair[:4], arm) not in schedule for pair in schedule for arm in ARMS):
        raise ValueError("Every planned case/repetition/stratum needs both arms")
    attempts = {}
    seen_ids = set()
    for attempt in results["attempts"]:
        identity = (*key(attempt), attempt["arm"])
        if identity not in schedule or identity in attempts or attempt["attempt_id"] in seen_ids:
            raise ValueError("Unplanned or duplicate arm/case; aggregate retries without dropping failures")
        seen_ids.add(attempt["attempt_id"])
        case = cases[attempt["case_id"]]
        if attempt["case_digest"] != case["case_digest"]:
            raise ValueError("Attempt source/truth/scope identity differs from frozen case")
        for field in PROTOCOL["pair_identity"]:
            value = attempt["identity"].get(field)
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError(f"Missing or invalid measured identity: {field}")
        assigned = attempt["coverage"]["assigned_units"]
        validated = attempt["coverage"]["validated_units"]
        if not isinstance(assigned, int) or isinstance(assigned, bool) or assigned != case["expected_assigned_units"] or not isinstance(validated, int) or isinstance(validated, bool) or not 0 <= validated <= assigned:
            raise ValueError("Coverage does not match frozen assigned denominator")
        for field in USAGE_FIELDS:
            value = attempt["usage"].get(field)
            if value is not None and not number(value):
                raise ValueError(f"Invalid usage: {field}")
        if any(value is not None and not number(value) for value in attempt["timing_ms"].values()):
            raise ValueError("Invalid measured duration")
        finding_ids = [finding["finding_id"] for finding in attempt["findings"]]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("Duplicate finding identity")
        attempts[identity] = attempt
    for identity, item in schedule.items():
        if identity not in attempts:
            attempts[identity] = {
                **item, "attempt_id": "not-started:" + ":".join(map(str, identity)),
                "case_digest": cases[item["case_id"]]["case_digest"],
                "identity": {}, "status": "not_started", "findings": [],
                "coverage": {"assigned_units": cases[item["case_id"]]["expected_assigned_units"], "validated_units": 0},
                "timing_ms": {}, "usage": {}, "outcomes": ["planned_not_started"],
            }
    return list(attempts.values())


def blind_id(attempt, finding):
    return hashlib.sha256(canonical([attempt["attempt_id"], finding])).hexdigest()


def blind_evidence(value):
    """Remove execution provenance, retaining semantic claims and exact evidence."""
    if isinstance(value, dict):
        private = {"arm", "engine", "analysis_engine", "provider", "model", "connection_id", "request_id", "response_id", "task_id", "attempt_id"}
        return {key: blind_evidence(item) for key, item in value.items() if key.lower() not in private}
    if isinstance(value, list):
        return [blind_evidence(item) for item in value if not isinstance(item, str) or item.lower() not in {"ocr", "mortis"}]
    return value


def blind(results):
    manifest, cases = load_corpus()
    attempts = validate_results(results, manifest, cases)
    items, mapping = [], {}
    for attempt in attempts:
        case = cases[attempt["case_id"]]
        for finding in attempt["findings"]:
            opaque = blind_id(attempt, finding)
            # Only explicit presentation fields enter the arm-blinded packet.
            presentation = {field: blind_evidence(finding[field]) for field in ("title", "body", "description", "severity", "path", "start_line", "end_line", "evidence", "citations", "rule_id") if field in finding}
            items.append({
                "blind_id": opaque, "case_id": case["case_id"], "workload": case["workload"],
                "finding": presentation, "defects": case["truth"]["defects"],
                "selected_source": {path: case["source"]["head"][path] for path in case["selected_paths"] if path in case["source"]["head"]},
                "base_source": {path: source for path, source in case["source"]["base"].items() if path not in {entry["path"] for entry in case["excluded"]}},
            })
            mapping[opaque] = {"attempt_id": attempt["attempt_id"], "finding_id": finding["finding_id"], "arm": attempt["arm"]}
    random.Random(PROTOCOL["bootstrap"]["seed"]).shuffle(items)
    packet = {
        "schema": "mortis-engine-blinded-findings/v1", "corpus_digest": manifest["corpus_digest"],
        "results_sha256": digest(canonical(results)), "protocol_sha256": PROTOCOL_SHA256,
        "instructions": "Scorer-only packet. Independently assess each claim. Match at most one defect by cause/trigger/consequence/evidence; mark uncertain when proof is insufficient. Never send truth or this packet to engine workers. Do not consult the private arm key.",
        "judgment_fields": {"blind_id": "item identity", "verdict": "match|false_positive|uncertain", "defect_id": "truth ID for match, otherwise null", "semantic": dict.fromkeys(SEMANTIC_FIELDS, "boolean"), "citation_bounds_valid": "boolean", "rationale": "required evidence-based explanation"},
        "items": items,
    }
    private = {"schema": "mortis-engine-blind-key/v1", "packet_sha256": digest(canonical(packet)), "mapping": mapping}
    return packet, private


def judgments_by_id(documents, packet):
    expected_digest = digest(canonical(packet))
    items = {item["blind_id"]: item for item in packet["items"]}
    decisions = {}
    for document in documents:
        if document.get("schema") != "mortis-engine-judgments/v1" or document.get("packet_sha256") != expected_digest:
            raise ValueError("Judgments do not bind this blind packet")
        if document.get("arm_blinded") is not True or document.get("independent") is not True or document.get("reviewer_kind") not in {"human", "agent"} or not document.get("reviewer_id"):
            raise ValueError("Independent arm-blinded reviewer provenance is required")
        for decision in document["judgments"]:
            opaque = decision["blind_id"]
            if opaque not in items or opaque in decisions:
                raise ValueError("Unknown or multiply adjudicated finding; resolve disagreements independently")
            if decision.get("verdict") not in {"match", "false_positive", "uncertain"} or not decision.get("rationale"):
                raise ValueError("Invalid or unexplained semantic judgment")
            if decision["verdict"] == "match":
                if decision.get("defect_id") not in {item["id"] for item in items[opaque]["defects"]}:
                    raise ValueError("Match references a different case's truth")
                if any(decision.get("semantic", {}).get(field) is not True for field in SEMANTIC_FIELDS) or decision.get("citation_bounds_valid") is not True:
                    raise ValueError("A true positive requires semantic proof and valid source bounds")
            elif decision.get("defect_id") is not None:
                raise ValueError("Nonmatches cannot claim a truth identity")
            decisions[opaque] = decision
    return decisions


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def nearest_rank(values, percentile):
    return sorted(values)[max(0, math.ceil(len(values) * percentile) - 1)] if values else None


def metrics(rows):
    tp, fp, fn = (sum(row[field] for row in rows) for field in ("tp", "fp", "fn"))
    pending = sum(row["pending"] for row in rows)
    clean = [row for row in rows if row["clean"]]
    severity = {}
    for level in ("low", "medium", "high", "critical"):
        relevant = [item for row in rows for item in row["defects"] if item["severity"] == level]
        severity[level] = {"found": sum(item["found"] for item in relevant), "eligible": len(relevant), "recall": ratio(sum(item["found"] for item in relevant), len(relevant))}
    return {
        "tp": tp, "fp": fp, "fn": fn, "pending_findings": pending,
        "precision": ratio(tp, tp + fp) if not pending else None, "recall": ratio(tp, tp + fn),
        "macro_recall": statistics.mean(row["tp"] / (row["tp"] + row["fn"]) for row in rows if row["tp"] + row["fn"]) if tp + fn else None,
        "clean_case_fp_incidence": ratio(sum(row["fp"] > 0 for row in clean), len(clean)) if not any(row["pending"] for row in clean) else None,
        "clean_case_attempts": len(clean), "severity_recall": severity,
        "validated_coverage": ratio(sum(row["validated_units"] for row in rows), sum(row["assigned_units"] for row in rows)),
        "citation_bounds_valid_rate": ratio(sum(row["valid_citations"] for row in rows), sum(row["judged_citations"] for row in rows)),
        "semantic_supported_rate": ratio(sum(row["semantic_supported"] for row in rows), sum(row["judged_semantic"] for row in rows)),
    }


def quality_rows(attempts, cases, decisions):
    rows = []
    for attempt in attempts:
        case = cases[attempt["case_id"]]
        if case["evaluation_track"] != "quality_microcase":
            continue
        found, fp, pending, valid_citations, judged_citations, supported, judged_semantic = set(), 0, 0, 0, 0, 0, 0
        for finding in attempt["findings"]:
            decision = decisions.get(blind_id(attempt, finding))
            if not decision or decision["verdict"] == "uncertain":
                pending += 1
                continue
            if isinstance(decision.get("citation_bounds_valid"), bool):
                judged_citations += 1
                valid_citations += decision["citation_bounds_valid"]
            if all(isinstance(decision.get("semantic", {}).get(field), bool) for field in SEMANTIC_FIELDS):
                judged_semantic += 1
                supported += all(decision["semantic"].values())
            defect = decision.get("defect_id")
            if decision["verdict"] == "match" and defect not in found:
                found.add(defect)
            else:
                fp += 1
        defects = [{"id": defect["id"], "severity": defect["severity"], "found": defect["id"] in found} for defect in case["truth"]["defects"]]
        rows.append({
            "case_id": case["case_id"], "family_id": case["family_id"], "workload": case["workload"],
            "arm": attempt["arm"], "stratum": [attempt["graph"], attempt["cache"]], "repetition": attempt["repetition"],
            "tp": len(found), "fp": fp, "fn": len(defects) - len(found), "pending": pending,
            "defects": defects, "clean": case["truth"]["expected"] == "clean", **attempt["coverage"],
            "valid_citations": valid_citations, "judged_citations": judged_citations,
            "semantic_supported": supported, "judged_semantic": judged_semantic,
        })
    return rows


def paired_bootstrap(rows):
    families = sorted({row["family_id"] for row in rows})
    grouped = {}
    for family in families:
        grouped[family] = [sum(row[field] for row in rows if row["family_id"] == family and row["arm"] == arm) for arm in ARMS for field in ("tp", "fp", "fn", "pending")]
    observed = {arm: metrics([row for row in rows if row["arm"] == arm]) for arm in ARMS}
    fields = ("precision", "recall")
    differences = {field: observed["mortis"][field] - observed["ocr"][field] if all(observed[arm][field] is not None for arm in ARMS) else None for field in fields}
    samples = {field: [] for field in fields}
    rng = random.Random(PROTOCOL["bootstrap"]["seed"])
    for _ in range(PROTOCOL["bootstrap"]["resamples"]):
        sample = [grouped[family] for family in rng.choices(families, k=len(families))]
        totals = [sum(column) for column in zip(*sample, strict=True)]
        values = {}
        for arm, offset in (("ocr", 0), ("mortis", 4)):
            tp, fp, fn, pending = totals[offset:offset + 4]
            values[arm] = {"precision": ratio(tp, tp + fp) if not pending else None, "recall": ratio(tp, tp + fn)}
        for field in fields:
            if all(values[arm][field] is not None for arm in ARMS):
                samples[field].append(values["mortis"][field] - values["ocr"][field])
    result = {}
    for field in fields:
        values = samples[field]
        reasons = []
        if len(families) < PROTOCOL["bootstrap"]["minimum_families"]:
            reasons.append("tiny_family_sample")
        if len(values) != PROTOCOL["bootstrap"]["resamples"] or differences[field] is None:
            reasons.append("undefined_or_no_event_resamples")
        if not values or len(set(values)) <= 1:
            reasons.append("degenerate_bootstrap")
        result[field] = {"mortis_minus_ocr": differences[field], "one_sided_95_lower": nearest_rank(values, .05), "independent_families": len(families), "defined_resamples": len(values), "status": "inconclusive" if reasons else "descriptive", "reasons": reasons}
    return result


def performance(attempts):
    summaries = {}
    groups = defaultdict(list)
    for attempt in attempts:
        workload = "pr" if attempt["case_id"].startswith("pr-") else "security"
        groups[(workload, attempt["graph"], attempt["cache"], attempt["arm"])].append(attempt)
    for group, items in sorted(groups.items()):
        times = {field: [item["timing_ms"][field] for item in items if item["timing_ms"].get(field) is not None] for field in {field for item in items for field in item["timing_ms"]}}
        usage = {field: {"observed_sum": sum(item["usage"].get(field) or 0 for item in items), "unknown_attempts": sum(item["usage"].get(field) is None for item in items)} for field in USAGE_FIELDS}
        failures = [item for item in items if item["status"] not in {"complete", "completed"}]
        summaries["/".join(group)] = {"attempts": len(items), "statuses": {status: sum(item["status"] == status for item in items) for status in sorted({item["status"] for item in items})}, "timing_ms_all_statuses": {field: {"p50": nearest_rank(values, .5), "p95": nearest_rank(values, .95), "observed_attempts": len(values), "missing_attempts": len(items) - len(values)} for field, values in sorted(times.items())}, "failed_or_incomplete_durations": [{"attempt_id": item["attempt_id"], "status": item["status"], "timing_ms": item["timing_ms"]} for item in failures], "usage": usage}
    return summaries


def required_work_gaps(attempt, workload, scanner_sha=None):
    """Validated analysis coverage does not establish completion of later workflows."""
    gaps = []
    stages = attempt.get("stages")
    if not isinstance(stages, dict):
        gaps.append("missing_stage_evidence")
        stages = {}
    verification_zero = False
    if workload == "pr":
        if not isinstance(attempt.get("summary"), dict) or attempt["summary"].get("status") != "completed":
            gaps.append("summary_not_completed_or_missing")
        progress = attempt.get("progress")
        if not isinstance(progress, dict) or progress.get("analysis_status") != "completed":
            gaps.append("analysis_not_completed_or_missing")
        candidates = attempt.get("candidates")
        if not isinstance(candidates, list) or any(not isinstance(row, dict) or row.get("status") != "completed" for row in candidates):
            gaps.append("assessment_not_completed_or_missing")
        verification = progress.get("verification") if isinstance(progress, dict) else None
        selection, targets = attempt.get("verification_selection"), attempt.get("verification_targets")
        if selection is not None or targets is not None:
            if not isinstance(selection, dict) or selection.get("observed") is not True or type(selection.get("selected")) is not int or selection["selected"] < 0 or not isinstance(targets, list) or selection["selected"] != len(targets):
                gaps.append("missing_verification_outcomes")
            elif any(not isinstance(row, dict) or row.get("status") != "completed" or row.get("verdict") not in {"fixed", "still_present"} or row.get("error") for row in targets):
                gaps.append("verification_not_completed")
            else:
                verification_zero = selection["selected"] == 0
        elif not isinstance(verification, dict) or any(type(verification.get(field)) is not int or verification[field] < 0 for field in ("selected", "completed", "failed", "skipped", "uncertain", "pending", "sync_failed")):
            gaps.append("missing_verification_outcomes")
        elif verification["completed"] != verification["selected"] or any(verification[field] for field in ("failed", "skipped", "uncertain", "pending", "sync_failed")):
            gaps.append("verification_not_completed")
        else:
            verification_zero = verification["selected"] == 0
        # Sequential PR runs use explicit progress/candidate/summary evidence instead of populated stage rows.
        expected = stages
    else:
        expected = dict.fromkeys(("snapshot", "trivy", "analysis", "assessment", "verification", "report"))
        observed = attempt.get("report")
        for key in ("coverage", "trivy", "evaluation_snapshot"):
            observed = observed.get(key) if isinstance(observed, dict) else None
        if not scanner_sha:
            gaps.append("missing_frozen_scanner_identity")
        elif not isinstance(observed, dict) or observed.get("before") != scanner_sha or observed.get("after") != scanner_sha:
            gaps.append("scanner_snapshot_evidence_missing_or_changed")
    for name in expected:
        stage = stages.get(name)
        if not isinstance(stage, dict) or stage.get("status") != "completed":
            if name == "verification" and verification_zero and isinstance(stage, dict) and stage.get("status") == "skipped" and not stage.get("error"):
                continue
            gaps.append("stage_" + name + "_not_completed_or_missing")
    return gaps


def paired_performance(pairs, cases, scanner_sha=None):
    groups = defaultdict(list)
    for pair, arms in pairs.items():
        groups[(cases[pair[0]]["workload"], pair[2], pair[3])].append(arms)
    result = {}
    for group, members in sorted(groups.items()):
        blockers = set()
        eligible = defaultdict(list)
        for arms in members:
            if any(arms["ocr"]["identity"].get(field) != arms["mortis"]["identity"].get(field) for field in PROTOCOL["pair_identity"]):
                blockers.add("pair_identity_mismatch")
                continue
            if any(item["status"] not in {"complete", "completed"} or item["coverage"]["validated_units"] != item["coverage"]["assigned_units"] or not item["coverage"]["assigned_units"] for item in arms.values()):
                blockers.add("incomplete_required_work_or_no_target")
                continue
            if any(required_work_gaps(item, group[0], scanner_sha) for item in arms.values()):
                blockers.add("incomplete_required_workflow")
                continue
            if any(not number(item["timing_ms"].get("terminal")) or not item["timing_ms"]["terminal"] for item in arms.values()):
                blockers.add("missing_or_zero_terminal_duration")
                continue
            if any(any(item["usage"].get(field) is None for field in USAGE_FIELDS) for item in arms.values()):
                blockers.add("unknown_consumption")
            family = cases[arms["ocr"]["case_id"]]["family_id"]
            eligible[family].append((arms["ocr"]["timing_ms"]["terminal"], arms["mortis"]["timing_ms"]["terminal"]))
        families = sorted(eligible)
        sample = [item for family in families for item in eligible[family]]
        ratios = {"p50": [], "p95": []}
        rng = random.Random(PROTOCOL["bootstrap"]["seed"])
        for _ in range(PROTOCOL["bootstrap"]["resamples"] if families else 0):
            draw = [item for family in rng.choices(families, k=len(families)) for item in eligible[family]]
            for name, quantile in (("p50", .5), ("p95", .95)):
                ratios[name].append(nearest_rank([item[1] for item in draw], quantile) / nearest_rank([item[0] for item in draw], quantile))
        bounds = {}
        for name, quantile in (("p50", .5), ("p95", .95)):
            reasons = []
            if len(families) < PROTOCOL["bootstrap"]["minimum_families"]:
                reasons.append("tiny_family_sample")
            if len(set(ratios[name])) <= 1:
                reasons.append("degenerate_or_no_event_bootstrap")
            bounds[name] = {"mortis_over_ocr": nearest_rank([item[1] for item in sample], quantile) / nearest_rank([item[0] for item in sample], quantile) if sample else None, "one_sided_95_upper": nearest_rank(ratios[name], .95), "status": "inconclusive" if reasons else "descriptive", "reasons": reasons}
        result["/".join(group)] = {"planned_pairs": len(members), "eligible_completed_pairs": len(sample), "independent_families": len(families), "terminal_latency_ratios": bounds, "claim_blockers": sorted(blockers | {"implementer_visible_synthetic_pilot_not_acceptance"}), "speedup_claim_allowed": False}
    return result


def score(results, documents=()):
    manifest, cases = load_corpus()
    attempts = validate_results(results, manifest, cases)
    packet, _ = blind(results)
    decisions = judgments_by_id(documents, packet)
    scanner_sha = (results.get("scanner_snapshot") or {}).get("sha256")
    rows = quality_rows(attempts, cases, decisions)
    groups = defaultdict(list)
    for row in rows:
        groups[(row["workload"], *row["stratum"])].append(row)
    quality = {}
    for group, items in sorted(groups.items()):
        quality["/".join(group)] = {"arms": {arm: metrics([row for row in items if row["arm"] == arm]) for arm in ARMS}, "paired_family_bootstrap": paired_bootstrap(items), "high_critical_truth": [{"case_id": row["case_id"], "arm": row["arm"], "repetition": row["repetition"], **defect} for row in items for defect in row["defects"] if defect["severity"] in {"high", "critical"}]}
    pairs = defaultdict(dict)
    for attempt in attempts:
        pairs[key(attempt)][attempt["arm"]] = attempt
    mismatches = [{"case": list(pair), "fields": [field for field in PROTOCOL["pair_identity"] if arms["ocr"]["identity"].get(field) != arms["mortis"]["identity"].get(field)]} for pair, arms in pairs.items()]
    mismatches = [item for item in mismatches if item["fields"]]
    return {
        "schema": "mortis-engine-score-report/v1", "protocol_sha256": PROTOCOL_SHA256,
        "corpus_digest": manifest["corpus_digest"], "results_sha256": digest(canonical(results)),
        "judgments_sha256": [digest(canonical(document)) for document in documents],
        "provenance": {"corpus": "implementer_visible_original_synthetic_pilot", "sealed_heldout": False, "independent_quality_families": len({row["family_id"] for row in rows})},
        "quality": quality, "performance": performance(attempts), "paired_performance": paired_performance(pairs, cases, scanner_sha), "pair_identity_mismatches": mismatches,
        "required_work_gaps": [{"case_id": attempt["case_id"], "arm": attempt["arm"], "repetition": attempt["repetition"], "gaps": gaps} for attempt in attempts if (gaps := required_work_gaps(attempt, cases[attempt["case_id"]]["workload"], scanner_sha))],
        "attempt_inventory": [{field: item[field] for field in ("attempt_id", "case_id", "arm", "repetition", "graph", "cache", "status", "coverage", "usage", "outcomes")} for item in attempts],
        "reliability_fixtures": [{"case_id": item["case_id"], "arm": item["arm"], "status": item["status"], "coverage": item["coverage"], "outcomes": item["outcomes"], "expected": "explicit incomplete/unsupported evidence; never clean"} for item in attempts if cases[item["case_id"]]["evaluation_track"] == "reliability_fixture"],
        "acceptance": "inconclusive", "speedup_claim_allowed": False,
        "limitations": PROTOCOL["missing_acceptance_strata"] + ["No quality or speed acceptance follows from this synthetic pilot; incomplete/pending outcomes remain explicit.", "Usage sums are observed subtotals; any unknown component prevents total billing/consumption claims."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    seal = sub.add_parser("freeze")
    seal.add_argument("--output", required=True, type=Path)
    packet = sub.add_parser("blind")
    packet.add_argument("--results", required=True, type=Path)
    packet.add_argument("--packet", required=True, type=Path)
    packet.add_argument("--key", required=True, type=Path)
    report = sub.add_parser("score")
    report.add_argument("--results", required=True, type=Path)
    report.add_argument("--judgments", action="append", type=Path, default=[])
    report.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "freeze":
        write_new(args.output, freeze())
    elif args.command == "blind":
        packet, private = blind(json.loads(args.results.read_text()))
        if args.packet.exists() or args.key.exists():
            parser.error("Packet and private key destinations must both be new")
        write_new(args.packet, packet)
        write_new(args.key, private)
    else:
        report = score(json.loads(args.results.read_text()), [json.loads(path.read_text()) for path in args.judgments])
        write_new(args.output, report)
    print(f"Scoring {args.command} complete; external requests: 0")


if __name__ == "__main__":
    main()
