"""Prospective, offline M5 acceptance. Never loads or re-scores the visible pilot.

The seal and corpus contain scorer-only truth. Keep them outside worker mounts.
All inputs are evidence supplied by the evaluator; a hash binds evidence, it does
not establish that a claimed independent review or sealed holdout actually exists.
"""

import argparse
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import score as pilot

ARMS = ("ocr", "mortis")
IDENTITIES = tuple(pilot.PROTOCOL["pair_identity"])
RELIABILITY_CHECKS = {
    "worker_loss", "duplicate_delivery", "cancellation", "revocation", "changed_head",
    "provider_failure", "uncertain_publication", "uncertain_consumption", "coverage",
    "no_duplicate_publication", "no_silent_resolution", "immutable_history", "authorization",
    "secret_handling", "endpoint_restrictions", "no_fallback", "full_workflow_recovery",
    "combined_capacity", "resource_headroom", "production_code_paths", "retained_features",
}
CORPUS_STRATA = {
    "clean", "historical_defects", "critical_defects", "cross_file", "large_changes",
    "other_languages", "documentation_config", "renames_deletions", "excluded_source",
    "missing_evidence", "unsupported_formats", "graph_gaps", "default_parallel_pr",
    "historical_verification", "security_above_concurrency", "overlapping_workloads",
}
PERFORMANCE_BEHAVIORS = {"analysis", "assessment", "historical_verification", "summary", "security_scanner", "cross_file_source", "clean_case", "single_file_source"}
REQUIRED_USAGE_FIELDS = {"requests", "tokens", "input_tokens", "output_tokens"}
CAP_FIELDS = {"aggregate_request_cap": "requests", "aggregate_token_cap": "tokens", "aggregate_usd_cap": "cost_usd"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def positive_int(value):
    return type(value) is int and value > 0


def timestamp(value):
    parsed = datetime.fromisoformat(value)
    require(parsed.tzinfo is not None, "Timestamp must include timezone")
    return parsed


def stratum(item):
    return "/".join(item[field] for field in ("workload", "graph", "cache"))


def block_inference(protocol):
    return protocol.get("performance_inference", {}).get("mode") == "fixed_matrix_blocks"


def block_order(cases, protocol, block_ids):
    """Freeze pair and arm order from identities, never from measured timings."""
    rng = random.Random(protocol["performance_inference"]["order_seed"])
    order = []
    for repetition, block_id in enumerate(block_ids, 1):
        pairs = [(case["case_id"], repetition, comparison["graph"], comparison["cache"])
                 for case in sorted(cases.values(), key=lambda case: case["case_id"])
                 for comparison in sorted(protocol["comparisons"], key=stratum)
                 if case["workload"] == comparison["workload"]]
        rng.shuffle(pairs)
        for pair in pairs:
            arms = list(ARMS)
            rng.shuffle(arms)
            order.extend((block_id, (*pair, arm)) for arm in arms)
    return order


def validate_protocol(protocol):
    require(protocol.get("schema") in {"mortis-engine-acceptance-protocol/v2", "mortis-engine-acceptance-protocol/v3"},
            "Unsupported acceptance protocol")
    if protocol["schema"] == "mortis-engine-acceptance-protocol/v3":
        eligibility = protocol.get("quality_eligibility", {})
        require(isinstance(eligibility, dict) and eligibility.get("mode") == "fully_executed_security_assessment_uncertainty"
                and eligibility.get("owner_approved") is True and sha(eligibility.get("approval_sha256"))
                and protocol.get("quality_acceptance", {}).get("mode") == "frozen_corpus",
                "Prospective security assessment eligibility requires explicit owner approval and finite-corpus rules")
    else:
        require("quality_eligibility" not in protocol, "New eligibility requires protocol v3; legacy rules stay strict")
    require(protocol.get("repository_scope") == ["wilfredinni/code-mortis"], "Owner-selected representative scope is Code Mortis only")
    require(protocol.get("version") and protocol.get("approved_by"), "Protocol version/owner approval pending")
    quality_rule = protocol.get("quality_acceptance", {})
    require(quality_rule.get("mode", "population_confidence") in {"population_confidence", "frozen_corpus"},
            "Unknown quality acceptance rule")
    if quality_rule.get("mode") == "frozen_corpus":
        require(quality_rule.get("owner_approved") is True
                and quality_rule.get("population_confidence") == "descriptive_only"
                and quality_rule.get("no_high_critical_loss") is True,
                "Frozen-corpus acceptance needs explicit owner approval and unchanged severe-loss protection")
    experts = protocol.get("independent_reviewer_ids")
    require(isinstance(experts, list) and experts and all(isinstance(item, str) and item.strip() for item in experts)
            and len(set(experts)) == len(experts), "Freeze identities of actual independent acceptance reviewers")
    require(set(protocol.get("allowed_signoff_kinds", [])) and set(protocol["allowed_signoff_kinds"])
            <= {"human", "external_expert", "independent_agent"}, "Freeze actual accepted reviewer kinds")
    materiality = protocol.get("materiality", {})
    require(sha(materiality.get("baseline_calibration_sha256")) and materiality.get("rationale")
            and materiality.get("calibration_kind") == "controlled_ocr_engine_overhead"
            and materiality.get("selected_before_acceptance") is True, "Independent latency materiality calibration pending")
    measurement = protocol.get("performance_measurement", {})
    require(measurement.get("mode") == "deterministic_local_provider"
            and measurement.get("metric") == "queue_to_terminal_ms" and measurement.get("endpoint_scope") == "loopback_only"
            and type(measurement.get("configured_provider_delay_ms")) is int and measurement["configured_provider_delay_ms"] == 0
            and sha(measurement.get("response_fixture_sha256")), "Freeze controlled local response fixture and timing mode; live provider latency is ineligible")
    bootstrap = protocol.get("bootstrap", {})
    require(bootstrap.get("confidence") == .95 and type(bootstrap.get("seed")) is int
            and positive_int(bootstrap.get("resamples")) and bootstrap["resamples"] >= 1000
            and positive_int(bootstrap.get("minimum_families")) and bootstrap["minimum_families"] >= 20,
            "Freeze family bootstrap seed, >=1000 resamples, >=20 families and one-sided 95% bounds")
    design = protocol.get("performance_inference")
    if design is not None:
        require(block_inference(protocol)
                and design.get("schema") == "mortis-engine-fixed-matrix-block-inference/v1"
                and positive_int(design.get("blocks")) and design["blocks"] >= 20
                and type(design.get("minimum_blocks")) is int and design["minimum_blocks"] >= 20
                and design["blocks"] >= design["minimum_blocks"]
                and type(design.get("order_seed")) is int
                and design.get("case_weighting") == "equal_fixed_cases"
                and design.get("profilewise_required") is True
                and design.get("confidence_method") == "paired_block_percentile_bootstrap"
                and design.get("scope") == "conditional_frozen_matrix"
                and design.get("stopping_rule") == "fixed_n_no_early_acceptance"
                and design.get("chosen_before_outputs") is True
                and design.get("sample_size_rationale") and design.get("limitations"),
                "Freeze independent paired blocks, fixed sample size, seed, profile gates and conditional confidence limits")
        require(quality_rule.get("mode") == "frozen_corpus", "Block protocol requires owner-approved finite-corpus quality")
        require({stratum(item) for item in protocol.get("quality_comparisons", [])}
                == {"pr/off/cold", "security/off/cold"}
                and len(protocol["quality_comparisons"]) == 2,
                "Freeze separate once-per-case quality comparisons; graph/cache features need separate checks")
    for sampling in (("quality_sampling", "performance_sampling") if block_inference(protocol)
                     else ("sampling", "performance_sampling")):
        for workload in ("pr", "security"):
            sample = protocol.get(sampling, {}).get(workload, {})
            require(positive_int(sample.get("minimum_cases")) and positive_int(sample.get("repetitions")),
                    "Explicit quality/performance sample/repetition requirements pending")
            require(sample["repetitions"] >= 3 or sample.get("repetition_rationale"),
                    "Fewer than three paired repetitions require a frozen practical rationale")
            if block_inference(protocol):
                if sampling == "quality_sampling":
                    require(positive_int(sample.get("minimum_families")) and sample["minimum_families"] >= 19
                            and sample["minimum_cases"] >= 38 and sample["repetitions"] == 1,
                            "Freeze >=38 quality cases and >=19 actual families per workload, evaluated once")
                else:
                    require(sample["minimum_cases"] >= 2 and sample["repetitions"] == design["blocks"],
                            "Every fixed performance block must retain at least two profiles per workload")
    comparisons = protocol.get("comparisons", [])
    require(isinstance(comparisons, list) and comparisons, "Required comparisons pending")
    names = set()
    for comparison in comparisons:
        require(comparison.get("workload") in {"pr", "security"}
                and comparison.get("graph") in {"off", "on", "gap"}
                and comparison.get("cache") in {"cold", "warm"}, "Unknown acceptance stratum")
        name = stratum(comparison)
        require(name not in names, "Duplicate acceptance stratum")
        names.add(name)
        for percentile in ("p50", "p95"):
            margin = comparison.get("latency", {}).get(percentile, {})
            require(pilot.number(margin.get("absolute_ms")) and pilot.number(margin.get("relative_fraction"))
                    and margin.get("combine") in {"both", "either"}, "Explicit absolute/relative latency margins and combination pending")
            if block_inference(protocol):
                require(margin == {"absolute_ms": 1000 if percentile == "p50" else 2000,
                                   "relative_fraction": .05 if percentile == "p50" else .1, "combine": "both"},
                        "Block mode preserves both frozen absolute and relative latency caps")
    if block_inference(protocol):
        require(names == {f"{workload}/{graph}/{cache}" for workload in ("pr", "security")
                          for graph in ("off", "on", "gap") for cache in ("cold", "warm")},
                "Block mode requires all twelve workload/graph/cache cells")
    require(protocol.get("strata_rationale"), "Justify the prospective workload/graph/cache strata")
    for workload in ("pr", "security"):
        declared = [item for item in comparisons if item["workload"] == workload]
        require({item["graph"] for item in declared} == {"off", "on", "gap"}
                and {item["cache"] for item in declared} == {"cold", "warm"},
                "Declare separate PR/security, graph off/on/gap and cold/warm comparisons")
    require(set(protocol.get("required_reliability_checks", [])) >= RELIABILITY_CHECKS,
            "Required reliability/feature/resource checks missing")
    require(set(protocol.get("required_corpus_strata", [])) >= CORPUS_STRATA, "Required representative strata missing")
    require(sha(protocol.get("execution_profile_sha256")), "Frozen resource/budget/deadline profile pending")
    required_usage = protocol.get("required_usage_fields", [])
    require(isinstance(required_usage, list) and set(required_usage) >= REQUIRED_USAGE_FIELDS
            and set(required_usage) <= set(pilot.USAGE_FIELDS) and len(set(required_usage)) == len(required_usage),
            "Freeze required request/input/output/total usage fields")
    require(protocol.get("comparison_usage_fields") == ["requests", "tokens"],
            "Prospective paired consumption compares requests and total tokens")
    spending = protocol.get("spending", {})
    require(spending.get("mode") in {"explicit_owner_uncapped", "finite"}
            and spending.get("stop_on_unknown_usage") is True and all(field in spending for field in CAP_FIELDS),
            "Freeze explicit spending policy without weakening unknown-consumption stops")
    caps = [spending[field] for field in CAP_FIELDS]
    require(all(cap is None or pilot.number(cap) for cap in caps)
            and (all(cap is None for cap in caps) if spending["mode"] == "explicit_owner_uncapped"
                 else any(cap is not None for cap in caps)), "Spending caps conflict with selected policy")
    require(all(spending[field] is None or metric in required_usage for field, metric in CAP_FIELDS.items()),
            "Every finite cap requires a known observable metric; unknown USD cannot enforce a USD cap")
    require(spending["aggregate_usd_cap"] is None,
            "This selected-provider acceptance protocol has no observed USD billing binding; a USD cap is ineligible")


def validate_corpus(corpus, protocol):
    require(corpus.get("schema") == "mortis-engine-acceptance-corpus/v2", "Unsupported acceptance corpus")
    require(corpus.get("repositories") == protocol["repository_scope"], "Heldout corpus differs from selected repository scope")
    require(corpus.get("sealed_heldout") is True and corpus.get("implementer_visible") is False
            and sha(corpus.get("provenance_evidence_sha256")), "Sealed independent heldout provenance required; pilot is ineligible")
    provenance = corpus.get("provenance", {})
    require(fingerprint(provenance) == corpus["provenance_evidence_sha256"]
            and provenance.get("custodian_id") and provenance.get("reviewer_id")
            and isinstance(provenance.get("implementer_ids"), list) and provenance["implementer_ids"]
            and isinstance(provenance.get("truth_author_ids"), list) and provenance["truth_author_ids"]
            and provenance["reviewer_id"] not in provenance["implementer_ids"]
            and provenance["custodian_id"] not in provenance["implementer_ids"]
            and sha(provenance.get("review_packet_sha256")) and sha(provenance.get("source_manifests_sha256")),
            "Independent custody/review packet identities and source-manifest binding required")
    timestamp(provenance["sealed_at"])
    evidence = corpus.get("strata_evidence", {})
    require(all(sha(evidence.get(name)) for name in protocol["required_corpus_strata"]), "Representative corpus evidence missing")
    cases = {}
    for case in corpus.get("cases", []):
        require(case.get("case_id") and case["case_id"] not in cases and case.get("family_id")
                and case.get("repository") in protocol["repository_scope"]
                and case.get("workload") in {"pr", "security"} and sha(case.get("case_digest"))
                and positive_int(case.get("expected_assigned_units")), "Invalid/duplicate frozen case")
        require(case.get("evaluation_track") == "quality_microcase", "Acceptance quality cases must have explicit truth")
        require(isinstance(case.get("source_evidence"), dict) and case["source_evidence"],
                "Independent reviewers need the frozen source evidence or immutable source references")
        truth = case.get("truth", {})
        require(truth.get("expected") in {"clean", "defect"} and isinstance(truth.get("defects"), list)
                and bool(truth["defects"]) == (truth["expected"] == "defect"), "Frozen quality ground truth missing")
        ids = [defect.get("id") for defect in truth["defects"]]
        require(all(ids) and len(set(ids)) == len(ids)
                and all(defect.get("severity") in {"low", "medium", "high", "critical"}
                        for defect in truth["defects"]), "Invalid defect identities/severity")
        require(all(all(defect.get(field) for field in (*pilot.SEMANTIC_FIELDS, "proof"))
                    for defect in truth["defects"]), "Frozen defects need semantic evidence and independent proof")
        cases[case["case_id"]] = case
    reviewed = [{"case_id": case["case_id"], "case_digest": case["case_digest"],
                 "truth_sha256": fingerprint(case["truth"])} for case in corpus["cases"]]
    require(provenance.get("reviewed_cases_sha256") == fingerprint(reviewed), "Independent corpus review does not bind frozen truth/cases")
    for workload in ("pr", "security"):
        selected = [case for case in cases.values() if case["workload"] == workload]
        sample = protocol["quality_sampling" if block_inference(protocol) else "sampling"][workload]
        require(len(selected) >= sample["minimum_cases"], "Insufficient frozen cases")
        minimum_families = sample["minimum_families"] if block_inference(protocol) else protocol["bootstrap"]["minimum_families"]
        require(len({case["family_id"] for case in selected}) >= minimum_families,
                "Insufficient independent families")
        require(any(case["truth"]["expected"] == "clean" for case in selected)
                and any(defect["severity"] == "critical" for case in selected for defect in case["truth"]["defects"]),
                "Each workload needs actual clean cases and critical defects, beyond stratum labels")
    return cases


def validate_schedule(schedule, cases, protocol, sampling=None, comparisons=None):
    sampling = sampling or protocol["quality_sampling" if block_inference(protocol) else "sampling"]
    comparisons = comparisons if comparisons is not None else protocol["quality_comparisons" if block_inference(protocol) else "comparisons"]
    planned = {}
    for item in schedule:
        identity = (*pilot.key(item), item["arm"])
        require(item.get("case_id") in cases and item.get("arm") in ARMS and identity not in planned,
                "Unknown/duplicate planned attempt")
        require(positive_int(item.get("repetition")) and all(sha(item.get("identity", {}).get(field)) for field in IDENTITIES),
                "Freeze measured pair identities and repetitions")
        planned[identity] = item
    expected = set()
    for case in cases.values():
        for comparison in comparisons:
            if comparison["workload"] != case["workload"]:
                continue
            for repetition in range(1, sampling[case["workload"]]["repetitions"] + 1):
                pair = (case["case_id"], repetition, comparison["graph"], comparison["cache"])
                for arm in ARMS:
                    expected.add((*pair, arm))
                if all((*pair, arm) in planned for arm in ARMS):
                    require(planned[(*pair, "ocr")]["identity"] == planned[(*pair, "mortis")]["identity"],
                            "Planned pair identity mismatch")
    require(set(planned) == expected, "Schedule must retain every frozen paired case/repetition/stratum")
    return planned


def validate_performance_plan(plan, quality_cases, protocol):
    blocks = block_inference(protocol)
    require(isinstance(plan, dict) and plan.get("schema") == ("mortis-engine-controlled-performance-plan/v3" if blocks
                                                            else "mortis-engine-controlled-performance-plan/v2"),
            "Separate visible controlled-performance case plan required")
    require(positive_int(plan.get("analysis_concurrency")), "Freeze controlled security analysis concurrency")
    require(plan.get("response_fixture_sha256") == protocol["performance_measurement"]["response_fixture_sha256"]
            and sha(plan.get("semantic_equivalence_evidence_sha256")) and sha(plan.get("family_provenance_sha256"))
            and set(plan.get("required_behaviors", [])) >= PERFORMANCE_BEHAVIORS,
            "Freeze equivalent nontrivial PR/security fixture behavior and family evidence")
    cases = {case["case_id"]: case for case in plan.get("cases", [])}
    require(cases and len(cases) == len(plan["cases"]) and not cases.keys() & quality_cases.keys(),
            "Performance fixtures must be separate from sealed quality cases")
    for case in cases.values():
        require(case.get("workload") in {"pr", "security"} and case.get("family_id") and sha(case.get("case_digest"))
                and positive_int(case.get("expected_assigned_units"))
                and set(case) == ({"case_id", "family_id", "workload", "case_digest", "expected_assigned_units", "expected_work"}
                                  | ({"profile_id"} if blocks else set())),
                "Controlled performance cases need truth-free identities and frozen case behavior")
        work = case["expected_work"]
        require(set(work) == {"findings", "assessment_candidates", "historical_verification_targets", "source_files", "security_analysis_tasks"}
                and all(type(value) is int and value >= 0 for value in work.values())
                and work["source_files"] == case["expected_assigned_units"], "Invalid per-case performance behavior counts")
        require(work["security_analysis_tasks"] == (work["source_files"] if case["workload"] == "security" else 0),
                "Security analysis counts must match assigned source files; PR cases cannot claim security tasks")
    for workload in ("pr", "security"):
        relevant = [case for case in cases.values() if case["workload"] == workload]
        require(len(relevant) >= protocol["performance_sampling"][workload]["minimum_cases"]
                and (blocks or len({case["family_id"] for case in relevant}) >= protocol["bootstrap"]["minimum_families"]),
                "Inadequate independent controlled-performance families/cases")
        if blocks:
            require(all(isinstance(case.get("profile_id"), str) and case["profile_id"].strip() for case in relevant)
                    and len({case["profile_id"] for case in relevant}) == len(relevant),
                    "Each workload needs distinct frozen profile identities for no-masking gates")
            require(any(case["expected_work"]["source_files"] == 1
                        and case["expected_work"]["findings"] == case["expected_work"]["assessment_candidates"]
                        == case["expected_work"]["historical_verification_targets"] == 0 for case in relevant)
                    and any(case["expected_work"]["source_files"] > 1
                            and case["expected_work"]["findings"] > 0
                            and case["expected_work"]["assessment_candidates"] > 0
                            and case["expected_work"]["historical_verification_targets"] > 0 for case in relevant),
                    "Block profiles must include a clean single-file case and a nonempty cross-file assessment/history case")
        require(any(case["expected_work"]["assessment_candidates"] > 0 for case in relevant)
                and any(case["expected_work"]["historical_verification_targets"] > 0 for case in relevant)
                and any(case["expected_work"]["source_files"] > 1 for case in relevant)
                and any(case["expected_work"]["source_files"] == 1 for case in relevant)
                and any(case["expected_work"]["findings"] == case["expected_work"]["assessment_candidates"] == 0 for case in relevant),
                "Declared cases must include actual nontrivial assessment/history/cross-file and clean/single-file behavior")
    require(any(case["workload"] == "security" and case["expected_work"]["security_analysis_tasks"] > plan.get("analysis_concurrency", math.inf)
                for case in cases.values()), "Designate security analysis larger than frozen concurrency")
    schedule = validate_schedule(plan["schedule"], cases, protocol, protocol["performance_sampling"], protocol["comparisons"])
    if blocks:
        block_ids = plan.get("block_ids")
        require(isinstance(block_ids, list) and len(block_ids) == protocol["performance_inference"]["blocks"]
                and all(isinstance(value, str) and value.strip() for value in block_ids)
                and len(set(block_ids)) == len(block_ids), "Freeze unique complete performance block identities")
        require([(item.get("block_id"), (*pilot.key(item), item["arm"])) for item in plan["schedule"]]
                == block_order(cases, protocol, block_ids),
                "Performance schedule must retain the complete seeded randomized paired block order")
    return cases, schedule


def freeze(protocol, corpus, schedule, performance_schedule=None, *, frozen_at=None):
    validate_protocol(protocol)
    cases = validate_corpus(corpus, protocol)
    validate_schedule(schedule, cases, protocol)
    validate_performance_plan(performance_schedule, cases, protocol)
    when = frozen_at or datetime.now(UTC).isoformat()
    require(timestamp(corpus["provenance"]["sealed_at"]) <= timestamp(when), "Corpus custody must be sealed before acceptance freeze")
    return {"schema": "mortis-engine-acceptance-seal/v2", "frozen_at": when,
            "protocol": protocol, "corpus": corpus, "schedule": schedule, "performance_schedule": performance_schedule,
            "protocol_sha256": fingerprint(protocol), "corpus_sha256": fingerprint(corpus),
            "schedule_sha256": fingerprint(schedule), "scorer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "performance_schedule_sha256": fingerprint(performance_schedule),
            "helper_sha256": hashlib.sha256(Path(pilot.__file__).read_bytes()).hexdigest(),
            "authorization": "Scorer-only seal; no provider execution or public adoption authorized"}


def verify_seal(seal):
    require(seal.get("schema") == "mortis-engine-acceptance-seal/v2", "Unsupported acceptance seal")
    for field in ("protocol", "corpus", "schedule", "performance_schedule"):
        require(fingerprint(seal[field]) == seal.get(field + "_sha256"), "Frozen " + field + " drift")
    require(seal.get("scorer_sha256") == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            and seal.get("helper_sha256") == hashlib.sha256(Path(pilot.__file__).read_bytes()).hexdigest(),
            "Frozen scorer/helper drift; preserve old scorer version")
    validate_protocol(seal["protocol"])
    cases = validate_corpus(seal["corpus"], seal["protocol"])
    validate_performance_plan(seal["performance_schedule"], cases, seal["protocol"])
    require(timestamp(seal["corpus"]["provenance"]["sealed_at"]) <= timestamp(seal["frozen_at"]),
            "Corpus custody must be sealed before acceptance freeze")
    return cases, validate_schedule(seal["schedule"], cases, seal["protocol"])


def latency_bound(families, margin, quantile, bootstrap):
    """Resample complete paired families or blocks; apply caps inside each draw."""
    def statistic(pairs):
        baseline = pilot.nearest_rank([pair[0] for pair in pairs], quantile)
        candidate = pilot.nearest_rank([pair[1] for pair in pairs], quantile)
        absolute, relative = candidate - baseline, candidate / baseline - 1
        absolute_excess = absolute - margin["absolute_ms"]
        relative_excess = relative * baseline - margin["relative_fraction"] * baseline
        excess = (max if margin["combine"] == "both" else min)(absolute_excess, relative_excess)
        require(all(math.isfinite(value) for value in (absolute, relative, excess)), "Latency arithmetic overflow")
        return absolute, relative, excess

    names = sorted(families)
    pairs = [pair for family in names for pair in families[family]]
    if not pairs:
        return {"status": "inconclusive", "reasons": ["no_complete_pairs"]}
    point = statistic(pairs)
    rng = random.Random(bootstrap["seed"])
    samples = [statistic([pair for family in rng.choices(names, k=len(names)) for pair in families[family]])
               for _ in range(bootstrap["resamples"])]
    excesses = [sample[2] for sample in samples]
    upper = pilot.nearest_rank(excesses, .95)
    reasons = []
    blocks = bootstrap.get("unit") == "block"
    if len(names) < bootstrap["minimum_blocks" if blocks else "minimum_families"]:
        reasons.append("inadequate_independent_blocks" if blocks else "inadequate_independent_families")
    if len(set(excesses)) <= 1:
        reasons.append("degenerate_bootstrap")
    return {"status": "inconclusive" if reasons else "pass" if upper <= 0 else "not_established",
            "reasons": reasons, "independent_blocks" if blocks else "independent_families": len(names),
            "paired_observations": len(pairs),
            "absolute_ms": point[0], "relative_fraction": point[1], "margin_excess_ms": point[2],
            "one_sided_95_upper_excess_ms": upper, "margin": margin,
            "stretch_point_met": point[1] <= (-.5 if quantile == .5 else -.3)}


def quality_bounds(rows, bootstrap):
    families = sorted({row["family_id"] for row in rows})
    grouped = {family: [row for row in rows if row["family_id"] == family] for family in families}

    def differences(sample):
        observed = {arm: pilot.metrics([row for row in sample if row["arm"] == arm]) for arm in ARMS}
        return {field: observed["mortis"][field] - observed["ocr"][field]
                if all(observed[arm][field] is not None for arm in ARMS) else None
                for field in ("precision", "recall")}

    point = differences(rows)
    rng = random.Random(bootstrap["seed"])
    samples = [differences([row for family in rng.choices(families, k=len(families)) for row in grouped[family]])
               for _ in range(bootstrap["resamples"])] if families else []
    result = {}
    for field in ("precision", "recall"):
        values = [sample[field] for sample in samples if sample[field] is not None]
        reasons = []
        if len(families) < bootstrap["minimum_families"]:
            reasons.append("inadequate_independent_families")
        if len(values) != bootstrap["resamples"] or point[field] is None:
            reasons.append("undefined_or_no_event_resamples")
        if len(set(values)) <= 1:
            reasons.append("degenerate_bootstrap")
        lower = pilot.nearest_rank(values, .05)
        result[field] = {"mortis_minus_ocr": point[field], "one_sided_95_lower": lower,
                         "status": "inconclusive" if reasons else "pass" if point[field] >= 0 and lower >= 0 else "not_established",
                         "reasons": reasons, "independent_families": len(families)}
    return result


def security_assessment_uncertainty_evidence(attempt):
    """Prove executed assessment abstentions; never change the retained product status."""
    try:
        require(attempt.get("workload") == "security" and attempt.get("status") == "partial", "Not a security partial")
        coverage, stages = attempt["coverage"], attempt["stages"]
        count = coverage["assigned_units"]
        require(positive_int(count) and type(coverage["validated_units"]) is int
                and coverage["validated_units"] == count, "Incomplete analysis coverage")
        phases = {"snapshot", "trivy", "analysis", "assessment", "verification", "report"}
        require(set(stages) == phases and all(isinstance(stage, dict) and not stage.get("error")
                and stage.get("status") == ("partial" if name == "assessment" else "completed")
                for name, stage in stages.items()), "Nonsemantic stage failure")
        tasks = attempt["progress"]["tasks"]
        require(isinstance(tasks, dict) and tasks and all(isinstance(key, str) and ":" in key
                and key.split(":", 1)[0] in {"analysis", "assessment", "verification"}
                and isinstance(task, dict) and task.get("status") == "completed"
                and sha(task.get("input_hash")) and isinstance(task.get("result"), dict)
                and type(task.get("tokens")) is int and task["tokens"] >= 0
                and not task.get("error") and not task.get("error_code") and not task["result"].get("error")
                and not task.get("validation_feedback")
                for key, task in tasks.items()), "Missing, failed or unknown task")
        grouped = {phase: {key.split(":", 1)[1]: task for key, task in tasks.items() if key.startswith(phase + ":")}
                   for phase in ("analysis", "assessment", "verification")}
        report = attempt["report"]
        inventory = report["coverage"]["inventory"]
        paths = {path for path, metadata in inventory.items() if metadata.get("code") is True}
        require(len(paths) == count and set(grouped["analysis"]) == paths
                and report["coverage"]["problems"] == [] and report["status"] == "partial",
                "Missing source/checkpoint evidence")
        proposals = []
        for task in grouped["analysis"].values():
            found = task["result"].get("findings")
            require(isinstance(found, list) and all(isinstance(proposal, dict) and proposal for proposal in found),
                    "Invalid analysis result")
            proposals.extend(found)
        assessed = list(grouped["assessment"].values())
        require(set(grouped["assessment"]) == {str(i) for i in range(len(proposals))}
                and Counter(map(fingerprint, proposals)) == Counter(fingerprint(task.get("proposal")) for task in assessed),
                "Candidate disappeared, duplicated or changed")
        require(all(task["result"].get("verdict") in {"confirmed", "rejected", "uncertain"} for task in assessed)
                and all(task["result"].get("verdict") in {"fixed", "still_present"}
                        for task in grouped["verification"].values()), "Invalid or uncertain verification result")
        uncertain = [task for task in assessed if task["result"]["verdict"] == "uncertain"]
        require(uncertain and all(not task.get("reused") for task in uncertain), "No fresh semantic abstention")
        expected_counts = {"analysis": {"total": count, "files": count, "completed": count, "failed": 0, "candidates": len(proposals)},
                           "assessment": {"total": len(proposals), "completed": len(proposals), "failed": 0},
                           "verification": {"total": len(grouped["verification"]), "completed": len(grouped["verification"])}}
        require(all(type(stages[phase].get(field)) is int and stages[phase][field] == value
                    for phase, values in expected_counts.items() for field, value in values.items()), "Incomplete stage counts")
        units = report["coverage"]["units"]
        require(isinstance(units, list) and len(units) == len(tasks)
                and {unit["task"]: {key: value for key, value in unit.items() if key != "task"} for unit in units}
                == {key: {field: value for field, value in task.items() if field not in {"result", "proposal"}}
                    for key, task in tasks.items()}, "Checkpoint/report inventory drift")
        unsettled = report["unsettled_candidates"]
        require(isinstance(unsettled, list) and Counter(map(fingerprint, unsettled))
                == Counter(fingerprint({"proposal": task["proposal"], "assessment": task["result"]}) for task in uncertain),
                "Uncertain candidate disappeared or changed")
        problems = ["A proposed security finding requires additional verification."] * len(uncertain)
        require(report["problems"] == problems and attempt.get("error") == "; ".join(problems)[:2000]
                and attempt.get("outcomes") == [] and attempt.get("stop_pilot") is False
                and not attempt["transport"].get("blocked_reason"), "Nonsemantic execution error")
        jobs = attempt["workflow_jobs"]
        require(isinstance(jobs, list) and jobs and attempt["job"] in jobs
                and len({job["id"] for job in jobs}) == len(jobs)
                and all(job.get("status") == "done" and not job.get("error") for job in jobs), "Unfinished workflow job")
        fields = ("status", "coverage", "stages", "progress", "report", "error", "outcomes", "stop_pilot", "transport", "job", "workflow_jobs")
        return {"schema": "mortis-security-assessment-execution-evidence/v1", "analysis_units": count,
                "assessed_candidates": len(proposals), "uncertain_assessments": len(uncertain),
                "operational_sha256": fingerprint({field: attempt[field] for field in fields})}
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def quality_work_gaps(attempt, workload, scanner_sha, protocol):
    gaps = pilot.required_work_gaps(attempt, workload, scanner_sha)
    coverage = attempt.get("coverage", {})
    if attempt.get("status") not in {"complete", "completed"} or coverage.get("validated_units") != coverage.get("assigned_units"):
        gaps.append("incomplete_validated_coverage_or_terminal_status")
    eligibility = protocol.get("quality_eligibility", {})
    if (protocol.get("schema") == "mortis-engine-acceptance-protocol/v3" and workload == "security"
        and eligibility.get("mode") == "fully_executed_security_assessment_uncertainty"
        and eligibility.get("owner_approved") is True and sha(eligibility.get("approval_sha256"))):
        proof = security_assessment_uncertainty_evidence(attempt)
        accounting = consumption_evidence(attempt, protocol)
        resource = attempt.get("resource_evidence")
        resource = resource if isinstance(resource, dict) else {}
        if (proof and attempt.get("semantic_uncertainty_evidence") == proof
            and not accounting["unknown_fields"] and not accounting["proof_gaps"]
            and not any(event.get("error_code") for event in attempt.get("provider_events", []))
            and resource.get("within_limits") is True and sha(resource.get("artifact_sha256"))
            and resource.get("profile_sha256") == protocol["execution_profile_sha256"]):
            gaps = [gap for gap in gaps if gap not in {"stage_assessment_not_completed_or_missing",
                                                     "incomplete_validated_coverage_or_terminal_status"}]
    return gaps


def quality_decision(bounds, protocol):
    """A finite-corpus comparison does not establish population-wide parity."""
    if protocol.get("quality_acceptance", {}).get("mode") != "frozen_corpus":
        return all(bound["status"] == "pass" for bound in bounds.values())
    return all(bound["mortis_minus_ocr"] is not None and bound["mortis_minus_ocr"] >= 0
               for bound in bounds.values())


def blind(results, corpus):
    """New packet schema; reuse the unchanged semantic-matching decision contract."""
    cases = {case["case_id"]: case for case in corpus["cases"]}
    items = []
    for attempt in results["attempts"]:
        case = cases[attempt["case_id"]]
        for finding in attempt["findings"]:
            presentation = {field: pilot.blind_evidence(finding[field]) for field in
                            ("title", "body", "description", "severity", "path", "start_line", "end_line", "evidence", "citations", "rule_id")
                            if field in finding}
            items.append({"blind_id": pilot.blind_id(attempt, finding), "case_id": case["case_id"],
                          "workload": case["workload"], "finding": presentation,
                          "defects": case["truth"]["defects"], "source_evidence": case.get("source_evidence", {})})
    random.Random(0).shuffle(items)
    return {"schema": "mortis-engine-acceptance-blinded-findings/v2", "results_sha256": fingerprint(results),
            "corpus_sha256": fingerprint(corpus), "items": items}


def controlled_performance(seal, results):
    if results is None:
        return {}, {"blockers": ["controlled_performance_results_pending"], "attempt_inventory": []}
    protocol = seal["protocol"]
    blocks = block_inference(protocol)
    cases, schedule = validate_performance_plan(seal["performance_schedule"], {}, protocol)
    require(results.get("schema") == ("mortis-engine-controlled-performance-results/v3" if blocks
                                      else "mortis-engine-controlled-performance-results/v2")
            and results.get("seal_sha256") == fingerprint(seal)
            and results.get("measurement") == seal["protocol"]["performance_measurement"],
            "Live quality/provider-network timings cannot enter controlled engine performance")
    require(timestamp(results["started_at"]) >= timestamp(seal["frozen_at"]), "Controlled run predates freeze")
    groups, seen, seen_ids, blockers, inventory = defaultdict(lambda: defaultdict(list)), set(), set(), set(), []
    pairs, valid_ids, observed_order = defaultdict(dict), set(), []
    for attempt in results["attempts"]:
        identity = (*pilot.key(attempt), attempt["arm"])
        require(identity in schedule and identity not in seen and isinstance(attempt.get("attempt_id"), str)
                and attempt["attempt_id"].strip() and attempt["attempt_id"] not in seen_ids,
                "Unknown/duplicate controlled-performance attempt")
        seen.add(identity)
        observed_order.append(identity)
        seen_ids.add(attempt.get("attempt_id"))
        if blocks:
            require(attempt.get("block_id") == schedule[identity]["block_id"], "Controlled attempt block identity mismatch")
        case = cases[attempt["case_id"]]
        require(attempt.get("case_digest") == case["case_digest"] and attempt.get("identity") == schedule[identity]["identity"],
                "Controlled fixture/pair identity drift")
        gaps = pilot.required_work_gaps(attempt, case["workload"], results.get("scanner_snapshot", {}).get("sha256"))
        work = attempt.get("nontrivial_work_evidence", {})
        work = work if isinstance(work, dict) else {}
        source_paths = work.get("source_paths")
        valid_paths = isinstance(source_paths, list) and all(isinstance(path, str) for path in source_paths)
        expected_work = case["expected_work"]
        if not (sha(work.get("artifact_sha256"))
                and all(type(work.get(field)) is int and work[field] == expected for field, expected in expected_work.items())
                and isinstance(attempt.get("findings"), list) and len(attempt["findings"]) == expected_work["findings"]
                and valid_paths and len(set(source_paths)) == expected_work["source_files"]):
            gaps.append("missing_or_mismatched_declared_work_evidence")
        if case["workload"] == "pr" and (work.get("assessment_candidates") != len(attempt.get("candidates", []))
                                          or work.get("historical_verification_targets") != len(attempt.get("verification_targets", []))):
            gaps.append("nontrivial_work_counters_do_not_match_retained_outcomes")
        if case["workload"] == "security":
            # OCR and Mortis share these validated workflow checkpoints; only Mortis has a gateway ledger.
            tasks = attempt.get("progress", {}).get("tasks", {})
            grouped = {phase: {key.split(":", 1)[1]: task for key, task in tasks.items() if key.startswith(phase + ":")}
                       for phase in ("analysis", "assessment", "verification")} if isinstance(tasks, dict) else {}
            records = [task for phase in grouped.values() for task in phase.values()]
            if (not valid_paths or set(grouped.get("analysis", {})) != set(source_paths)
                    or len(grouped.get("analysis", {})) != expected_work["security_analysis_tasks"]
                    or any(not isinstance(task, dict) or task.get("status") != "completed"
                           or not sha(task.get("input_hash")) or not isinstance(task.get("result"), dict)
                           for task in records)):
                gaps.append("security_analysis_counts_do_not_match_retained_tasks")
            stages = attempt.get("stages", {})
            analysis, assessment, verification = (stages.get(phase, {}) for phase in ("analysis", "assessment", "verification"))
            observed = [analysis.get("files"), analysis.get("completed"), analysis.get("failed"),
                        assessment.get("total"), assessment.get("completed"), assessment.get("failed"),
                        verification.get("total"), verification.get("completed")]
            expected = [expected_work["security_analysis_tasks"], expected_work["security_analysis_tasks"], 0,
                        expected_work["assessment_candidates"], expected_work["assessment_candidates"], 0,
                        expected_work["historical_verification_targets"], expected_work["historical_verification_targets"]]
            if (len(grouped.get("assessment", {})) != expected_work["assessment_candidates"]
                    or len(grouped.get("verification", {})) > expected_work["historical_verification_targets"]
                    or observed != expected or any(type(value) is not int for value in observed)):
                gaps.append("security_work_counters_do_not_match_retained_outcomes")
        coverage = attempt.get("coverage", {})
        timing = attempt.get("timing_ms")
        terminal = timing.get("terminal") if isinstance(timing, dict) else None
        complete = (attempt.get("status") in {"complete", "completed"}
                    and type(coverage.get("assigned_units")) is int and coverage["assigned_units"] == case["expected_assigned_units"]
                    and type(coverage.get("validated_units")) is int and coverage["validated_units"] == coverage["assigned_units"]
                    and not gaps and attempt.get("timing_origin") == "queued"
                    and pilot.number(terminal) and terminal > 0)
        resource = attempt.get("resource_evidence", {})
        measured = attempt.get("performance_evidence", {})
        transport = attempt.get("transport", {})
        declared = transport.get("declared_connection") if isinstance(transport, dict) else None
        base_url = declared.get("base_url") if isinstance(declared, dict) else None
        try:
            upstream = urlsplit(base_url if isinstance(base_url, str) else "")
        except ValueError:
            upstream = urlsplit("")
        valid = (isinstance(resource, dict) and isinstance(measured, dict) and isinstance(transport, dict)
                 and resource.get("profile_sha256") == seal["protocol"]["execution_profile_sha256"]
                 and resource.get("within_limits") is True and sha(resource.get("artifact_sha256"))
                 and measured.get("measurement") == seal["protocol"]["performance_measurement"]
                 and sha(measured.get("artifact_sha256"))
                 and transport.get("provider_mode") == "controlled_synthetic_http"
                 and upstream.scheme == "http" and upstream.hostname in {"127.0.0.1", "localhost", "::1"}
                 and not (upstream.username or upstream.password or upstream.query or upstream.fragment))
        if not complete or not valid:
            blockers.add("controlled_required_work_timing_or_resource_evidence_incomplete")
        accounting = consumption_evidence(attempt, protocol)
        accounting_ok = not accounting["unknown_fields"] and not accounting["proof_gaps"]
        if not accounting_ok:
            blockers.add("controlled_unknown_consumption")
        inventory.append({"attempt_id": attempt.get("attempt_id"), "status": attempt.get("status"),
                          "consumption": accounting,
                          **({"block_id": attempt["block_id"], "profile_id": case["profile_id"],
                              **{field: attempt[field] for field in ("case_id", "arm", "repetition", "graph", "cache")},
                              "usage": attempt.get("usage"), "provider_events": attempt.get("provider_events"),
                              "ledger": attempt.get("ledger")} if blocks else {}),
                          "coverage": coverage, "timing_ms": attempt.get("timing_ms", {}),
                          "resource_evidence": resource, "performance_evidence": measured,
                          "nontrivial_work_evidence": work, "required_work_gaps": gaps})
        if complete and valid and accounting_ok:
            pairs[pilot.key(attempt)][attempt["arm"]] = attempt
            valid_ids.add(identity)
    if seen != set(schedule):
        blockers.add("controlled_planned_attempts_missing")
    complete_blocks = set()
    if blocks:
        ordered = list(schedule)
        if observed_order != ordered[:len(observed_order)]:
            blockers.add("controlled_seeded_block_order_mismatch")
        else:
            complete_blocks = {block_id for block_id in seal["performance_schedule"]["block_ids"]
                               if all(key in valid_ids for key, item in schedule.items() if item["block_id"] == block_id)}
        if len(complete_blocks) != protocol["performance_inference"]["blocks"]:
            blockers.add("controlled_fixed_blocks_incomplete")
    for key, arms in pairs.items():
        if set(arms) == set(ARMS):
            case = cases[key[0]]
            name = "/".join((case["workload"], key[2], key[3]))
            unit = schedule[(*key, "ocr")]["block_id"] if blocks else case["family_id"]
            if blocks and unit not in complete_blocks:
                continue
            timing = tuple(arms[arm]["timing_ms"]["terminal"] for arm in ARMS)
            groups[name][unit].append(timing)
            if blocks:
                groups[name + "/profile/" + case["profile_id"]][unit].append(timing)
    return groups, {"blockers": sorted(blockers), "attempt_inventory": inventory,
                    "results_sha256": fingerprint(results),
                    **({"resampling_unit": "block", "planned_blocks": protocol["performance_inference"]["blocks"],
                        "complete_block_ids": sorted(complete_blocks), "scope": "conditional_frozen_matrix",
                        "confidence": "Nominal one-sided 95% paired block percentile bootstrap; no exact finite-sample coverage guarantee",
                        "limitations": protocol["performance_inference"]["limitations"]} if blocks else {}),
                    "measurement_note": "External provider latency excluded by local deterministic responses and zero configured delay; tiny local response processing/observer overhead remains included. Server wait is diagnostic, never subtracted from overlapping task durations."}


def consumption_evidence(attempt, protocol):
    usage = attempt.get("usage")
    if not isinstance(usage, dict):
        usage = {}
    unknown = [field for field in protocol["required_usage_fields"] if not pilot.number(usage.get(field))]
    optional = [field for field in pilot.USAGE_FIELDS if field not in protocol["required_usage_fields"]]
    optional_unknown = [field for field in optional if usage.get(field) is None]
    gaps = []
    for field in pilot.USAGE_FIELDS:
        if usage.get(field) is not None and (not pilot.number(usage[field])
                                            or field != "cost_usd" and type(usage[field]) is not int):
            gaps.append("invalid_usage_" + field)
    if (all(type(usage.get(field)) is int for field in REQUIRED_USAGE_FIELDS)
            and usage["tokens"] != usage["input_tokens"] + usage["output_tokens"]):
        gaps.append("inconsistent_usage_total")
    events = attempt.get("provider_events")
    if not isinstance(events, list):
        gaps.append("missing_provider_capture_evidence")
    else:
        forwarded = []
        sequences = []
        for event in events:
            if not isinstance(event, dict):
                gaps.append("invalid_provider_capture_event")
                continue
            sequences.append(event.get("sequence"))
            if type(event.get("forwarded")) is not bool or event.get("consumption_unknown") is not False:
                gaps.append("unknown_provider_consumption")
            if event.get("forwarded") is True:
                forwarded.append(event)
                fields = ("input_tokens", "output_tokens", "total_tokens")
                if (event.get("state") != "finished"
                    or any(type(event.get(field)) is not int or event[field] < 0 for field in fields)
                    or event.get("total_tokens") != event.get("input_tokens", 0) + event.get("output_tokens", 0)):
                    gaps.append("unfinished_or_inconsistent_provider_consumption")
        if sequences != list(range(1, len(events) + 1)):
            gaps.append("incomplete_or_duplicate_provider_capture_inventory")
        if usage.get("requests") != len(forwarded):
            gaps.append("capture_request_count_mismatch")
        for reported, captured in (("tokens", "total_tokens"), ("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")):
            values = [event.get(captured) for event in forwarded]
            if all(type(value) is int and value >= 0 for value in values) and usage.get(reported) != sum(values):
                gaps.append("capture_" + reported + "_mismatch")
    ledger = attempt.get("ledger")
    if not isinstance(ledger, dict) or not isinstance(ledger.get("attempts"), list) or not isinstance(ledger.get("tasks"), list):
        gaps.append("missing_durable_ledger_evidence")
    else:
        if attempt.get("arm") == "mortis" and pilot.number(usage.get("requests")) and usage["requests"] > 0 and not ledger["attempts"]:
            gaps.append("missing_mortis_durable_attempts")
        for row in ledger["attempts"]:
            if (not isinstance(row, dict) or row.get("usage_state") != "known"
                or row.get("status") not in {"completed", "failed"}
                or type(row.get("usage_tokens")) is not int or row["usage_tokens"] < 0
                or type(row.get("reserved_tokens")) is not int or row["reserved_tokens"] < 0):
                gaps.append("unknown_or_reserved_durable_consumption")
        amounts = [row.get("usage_tokens") for row in ledger["attempts"] if isinstance(row, dict)]
        if (all(type(amount) is int and amount >= 0 for amount in amounts) and pilot.number(usage.get("tokens"))
                and sum(amounts) > usage["tokens"]):
            gaps.append("durable_consumption_exceeds_captured_total")
        if any(not isinstance(row, dict) or row.get("status") in {"running", "uncertain"} for row in ledger["tasks"]):
            gaps.append("unsettled_durable_task")
    return {"attempt_id": attempt["attempt_id"], "usage": usage, "unknown_fields": unknown,
            "optional_unknown_fields": optional_unknown, "proof_gaps": sorted(set(gaps))}


def score(seal, results, documents=(), evidence=None, performance_results=None):
    cases, planned = verify_seal(seal)
    protocol, evidence = seal["protocol"], evidence if isinstance(evidence, dict) else {}
    controlled_groups, controlled = controlled_performance(seal, performance_results)
    require(results.get("schema") == "mortis-engine-acceptance-results/v2"
            and results.get("seal_sha256") == fingerprint(seal), "Results must bind prospective acceptance seal")
    require(timestamp(results["started_at"]) >= timestamp(seal["frozen_at"]), "Acceptance started before protocol freeze")
    attempts, seen, seen_ids = [], set(), set()
    blockers, gaps, resources, consumption, inventory = set(), [], [], [], []
    blockers.update(controlled["blockers"])
    for attempt in results["attempts"]:
        identity = (*pilot.key(attempt), attempt["arm"])
        require(identity in planned and identity not in seen and attempt.get("attempt_id")
                and attempt["attempt_id"] not in seen_ids, "Unplanned/duplicate attempt; retain retries in attempt accounting")
        seen.add(identity)
        seen_ids.add(attempt["attempt_id"])
        case = cases[attempt["case_id"]]
        require(attempt.get("case_digest") == case["case_digest"] and attempt.get("identity") == planned[identity]["identity"],
                "Attempt frozen case/settings/resources/conditions identity mismatch")
        require(len({finding["finding_id"] for finding in attempt["findings"]}) == len(attempt["findings"]), "Duplicate finding identity")
        coverage = attempt.get("coverage", {})
        require(type(coverage.get("assigned_units")) is int and coverage["assigned_units"] == case["expected_assigned_units"]
                and type(coverage.get("validated_units")) is int
                and 0 <= coverage["validated_units"] <= coverage["assigned_units"], "Invalid frozen coverage denominator")
        work_gaps = quality_work_gaps(attempt, case["workload"], results.get("scanner_snapshot", {}).get("sha256"), protocol)
        timing = attempt.get("timing_ms")
        terminal = timing.get("terminal") if isinstance(timing, dict) else None
        if not pilot.number(terminal) or not terminal:
            work_gaps.append("missing_queue_to_terminal_duration")
        if attempt.get("timing_origin") != "queued":
            work_gaps.append("queue_time_not_included")
        if work_gaps:
            gaps.append({"attempt_id": attempt["attempt_id"], "gaps": work_gaps})
            blockers.add("incomplete_required_work")
        usage_evidence = consumption_evidence(attempt, protocol)
        consumption.append(usage_evidence)
        if usage_evidence["unknown_fields"] or usage_evidence["proof_gaps"]:
            blockers.add("unknown_consumption")
        resource = attempt.get("resource_evidence", {})
        resource_ok = isinstance(resource, dict) and resource.get("profile_sha256") == protocol["execution_profile_sha256"] and resource.get("within_limits") is True and sha(resource.get("artifact_sha256"))
        resources.append({"attempt_id": attempt["attempt_id"], "evidence": resource, "valid": resource_ok})
        if not resource_ok:
            blockers.add("resource_budget_deadline_evidence_missing_or_violated")
        attempts.append(attempt)
        inventory.append({**{field: attempt.get(field) for field in ("attempt_id", "case_id", "arm", "repetition", "graph", "cache", "status", "timing_ms", "stages", "outcomes")},
                          **({"semantic_uncertainty_evidence": attempt.get("semantic_uncertainty_evidence")}
                             if protocol["schema"] == "mortis-engine-acceptance-protocol/v3" else {})})
    missing = sorted(set(planned) - seen)
    if missing:
        blockers.add("missing_planned_attempts")
    packet = blind(results, seal["corpus"])
    valid_documents = []
    for document in documents:
        if not isinstance(document, dict):
            blockers.add("independent_review_pending")
            continue
        valid_documents.append(document)
        excluded_reviewers = (seal["corpus"]["provenance"]["implementer_ids"]
                              + seal["corpus"]["provenance"]["truth_author_ids"])
        require(document.get("reviewer_id") not in excluded_reviewers,
                "Implementers and truth authors cannot provide independent acceptance judgments")
        if document.get("reviewer_kind") in {"human", "external_expert", "independent_agent"}:
            require(document.get("reviewer_id") in protocol["independent_reviewer_ids"],
                    "Acceptance reviewer identity was not independently designated before outputs")
    normalized = [{**document, "reviewer_kind": "human"} if document.get("reviewer_kind") == "external_expert"
                  else {**document, "reviewer_kind": "agent"} if document.get("reviewer_kind") == "independent_agent"
                  else document for document in valid_documents]
    decisions = pilot.judgments_by_id(normalized, packet)
    rows = pilot.quality_rows(attempts, cases, decisions)
    if any(row["pending"] for row in rows):
        blockers.add("unresolved_adjudication")
    severe_losses = [{"case_id": row["case_id"], "repetition": row["repetition"], "defect": defect}
                     for row in rows if row["arm"] == "mortis" for defect in row["defects"]
                     if defect["severity"] in {"high", "critical"} and not defect["found"]]
    if severe_losses:
        blockers.add("high_critical_loss")
    quality, performance = {}, {}
    pairs = defaultdict(dict)
    for attempt in attempts:
        pairs[pilot.key(attempt)][attempt["arm"]] = attempt
    for comparison in protocol["quality_comparisons" if block_inference(protocol) else "comparisons"]:
        name = stratum(comparison)
        quality_rows = [row for row in rows if "/".join((row["workload"], *row["stratum"])) == name]
        quality_bootstrap = protocol["bootstrap"]
        if block_inference(protocol):
            quality_bootstrap = {**quality_bootstrap, "minimum_families": protocol["quality_sampling"][comparison["workload"]]["minimum_families"]}
        quality[name] = {"arms": {arm: pilot.metrics([row for row in quality_rows if row["arm"] == arm]) for arm in ARMS},
                         "bounds": quality_bounds(quality_rows, quality_bootstrap)}
        for key, arms in pairs.items():
            if "/".join((cases[key[0]]["workload"], key[2], key[3])) != name or set(arms) != set(ARMS):
                continue
            usages = [arms[arm].get("usage") for arm in ARMS]
            for field in protocol["comparison_usage_fields"]:
                values = [usage.get(field) if isinstance(usage, dict) else None for usage in usages]
                if all(pilot.number(value) for value in values) and values[1] > values[0]:
                    blockers.add("paired_provider_consumption_regression")
    for comparison in protocol["comparisons"]:
        name = stratum(comparison)
        names = [name]
        performance_bootstrap = protocol["bootstrap"]
        if block_inference(protocol):
            names += [name + "/profile/" + case["profile_id"] for case in seal["performance_schedule"]["cases"]
                      if case["workload"] == comparison["workload"]]
            performance_bootstrap = {**protocol["bootstrap"], "unit": "block",
                                     "minimum_blocks": protocol["performance_inference"]["blocks"]}
        for group_name in names:
            performance[group_name] = {percentile: latency_bound(controlled_groups.get(group_name, {}), comparison["latency"][percentile], quantile, performance_bootstrap)
                                       for percentile, quantile in (("p50", .5), ("p95", .95))}
    for cap, metric in CAP_FIELDS.items():
        limit = protocol["spending"][cap]
        values = [attempt["usage"].get(metric) if isinstance(attempt.get("usage"), dict) else None
                  for attempt in attempts]
        if limit is not None and (not all(pilot.number(value) for value in values) or sum(values) > limit):
            blockers.add("finite_spending_cap_unknown_or_exceeded")
    checks = evidence.get("checks", {})
    checks = checks if isinstance(checks, dict) else {}
    evidence_bound = evidence.get("results_sha256") == fingerprint(results) and evidence.get("seal_sha256") == fingerprint(seal)
    reliability = {}
    for name in protocol["required_reliability_checks"]:
        check = checks.get(name)
        check = check if isinstance(check, dict) else {}
        reliability[name] = {**check, "valid": evidence_bound and check.get("status") == "passed"
                             and sha(check.get("artifact_sha256"))}
    if not all(item["valid"] for item in reliability.values()):
        blockers.add("reliability_feature_resource_evidence_incomplete")
    independent_reviews = evidence.get("independent_reviews", [])
    independent_reviews = independent_reviews if isinstance(independent_reviews, list) else []
    covered = set()
    expected_findings = {item["blind_id"] for item in packet["items"]}
    for review in independent_reviews:
        if not isinstance(review, dict):
            continue
        qualifying = [document for document in valid_documents
                      if document.get("reviewer_kind") == review.get("reviewer_kind")
                      and document.get("reviewer_id") == review.get("reviewer_id")
                      and fingerprint(document) == review.get("judgments_sha256")]
        if not (evidence_bound and review.get("reviewer_kind") in protocol["allowed_signoff_kinds"]
                and review.get("reviewer_id") in protocol["independent_reviewer_ids"]
                and review.get("independent") is True and review.get("arm_blinded") is True
                and review.get("status") == "passed" and sha(review.get("artifact_sha256"))
                and review.get("packet_sha256") == fingerprint(packet)):
            continue
        for document in qualifying:
            if document["reviewer_kind"] == "independent_agent" and not all(
                document.get(field) is True for field in
                ("fresh_review_context", "not_involved_in_implementation", "not_truth_author")
            ):
                continue
            covered.update(decision["blind_id"] for decision in document["judgments"])
    if not expected_findings or covered != expected_findings:
        blockers.add("independent_review_pending")
    for item in quality.values():
        item["acceptance_rule"] = protocol.get("quality_acceptance", {}).get("mode", "population_confidence")
        item["comparison_passed"] = quality_decision(item["bounds"], protocol)
    if not all(item["comparison_passed"] for item in quality.values()):
        blockers.add("quality_parity_not_established")
    if any(bound["status"] != "pass" for item in performance.values() for bound in item.values()):
        blockers.add("performance_nonregression_not_established")
    return {"schema": "mortis-engine-acceptance-report/v2", "seal_sha256": fingerprint(seal),
            "results_sha256": fingerprint(results), "judgments_sha256": [fingerprint(doc) for doc in documents],
            "evidence_sha256": fingerprint(evidence), "acceptance": "pass" if not blockers else "not_established",
            "blockers": sorted(blockers), "quality": quality, "high_critical_losses": severe_losses,
            "performance": performance, "reliability": reliability, "independent_reviews": independent_reviews, "independently_reviewed_findings": len(covered),
            "controlled_performance": controlled, "live_provider_timings": "Descriptive quality/reliability evidence only; excluded from the performance gate",
            "resources": resources, "consumption": consumption, "required_work_gaps": gaps,
            "attempt_inventory": inventory, "missing_planned_attempts": [list(item) for item in missing],
            "adoption_authorized": False, "limitations": ["Evidence hashes bind supplied records; independent custody and reviewer identities require external verification. Independent-agent signoff is owner-authorized and never constitutes human/external-expert review.",
                                                           "Stretch speedups are descriptive and never acceptance prerequisites.",
                                                           "Frozen-corpus quality acceptance, when explicitly selected, is limited to the sealed cases; confidence bounds remain descriptive and broader validation belongs to M6."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freezing = sub.add_parser("freeze")
    for field in ("protocol", "corpus", "schedule", "performance-schedule", "output"):
        freezing.add_argument("--" + field, type=Path, required=True)
    blinding = sub.add_parser("blind")
    blinding.add_argument("--seal", type=Path, required=True)
    blinding.add_argument("--results", type=Path, required=True)
    blinding.add_argument("--output", type=Path, required=True)
    scoring = sub.add_parser("score")
    for field in ("seal", "results", "evidence", "output"):
        scoring.add_argument("--" + field, type=Path, required=True)
    scoring.add_argument("--judgments", type=Path, action="append", default=[])
    scoring.add_argument("--performance-results", type=Path)
    args = parser.parse_args()
    def load(path):
        return json.loads(path.read_text())
    if args.command == "freeze":
        report = freeze(load(args.protocol), load(args.corpus), load(args.schedule), load(args.performance_schedule))
    elif args.command == "blind":
        seal, results = load(args.seal), load(args.results)
        verify_seal(seal)
        require(results.get("schema") == "mortis-engine-acceptance-results/v2"
                and results.get("seal_sha256") == fingerprint(seal), "Results do not bind prospective acceptance seal")
        require(timestamp(results["started_at"]) >= timestamp(seal["frozen_at"]), "Acceptance started before protocol freeze")
        report = blind(results, seal["corpus"])
    else:
        report = score(load(args.seal), load(args.results), [load(path) for path in args.judgments], load(args.evidence),
                       load(args.performance_results) if args.performance_results else None)
    pilot.write_new(args.output, report)


if __name__ == "__main__":
    main()
