"""Phase 0 experiment, not an application indexer. Run in the disposable container."""

import ast
import contextlib
import hashlib
import importlib
import importlib.metadata
import json
import platform
import resource
import sys
import time
from collections import Counter
from pathlib import Path

# shortcut: syntax probes cover selected node kinds, not complete language semantics;
# add language-specific acceptance fixtures before advertising further relationships.
LANGUAGES = {
    ".py": ("python", "function_definition class_definition", "call", "import_statement import_from_statement"),
    ".js": ("javascript", "function_declaration class_declaration method_definition", "call_expression", "import_statement export_statement"),
    ".jsx": ("javascript", "function_declaration class_declaration method_definition", "call_expression", "import_statement export_statement"),
    ".ts": ("typescript", "function_declaration class_declaration method_definition interface_declaration type_alias_declaration", "call_expression", "import_statement export_statement"),
    ".tsx": ("tsx", "function_declaration class_declaration method_definition interface_declaration type_alias_declaration", "call_expression", "import_statement export_statement"),
    ".go": ("go", "function_declaration method_declaration type_spec", "call_expression", "import_declaration"),
    ".rs": ("rust", "function_item struct_item enum_item trait_item", "call_expression", "use_declaration"),
    ".java": ("java", "class_declaration interface_declaration method_declaration constructor_declaration", "method_invocation", "import_declaration"),
    ".c": ("c", "function_definition struct_specifier", "call_expression", "preproc_include"),
    ".cpp": ("cpp", "function_definition class_specifier struct_specifier", "call_expression", "preproc_include"),
    ".rb": ("ruby", "method singleton_method class module", "call", ""),
    ".cs": ("c_sharp", "class_declaration interface_declaration method_declaration", "invocation_expression", "using_directive"),
    ".php": ("php", "function_definition class_declaration method_declaration", "function_call_expression", "require_expression include_expression"),
    ".sh": ("bash", "function_definition", "command", ""),
}


def descendants(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def relative_target(path, specifier, available, python=False, level=0):
    """Resolve only unambiguous, in-corpus relative file dependencies."""
    if python:
        if not level:
            return None
        base = path.parent
        for _ in range(level - 1):
            if base == Path("."):
                return None
            base = base.parent
        base = base.joinpath(*specifier.split(".")) if specifier else base
        candidates = [str(base) + ".py", str(base / "__init__.py")]
    else:
        if not specifier.startswith("."):
            return None
        parts = list(path.parent.parts)
        for part in specifier.split("/"):
            if part == "..":
                if not parts:
                    return None
                parts.pop()
            elif part not in ("", "."):
                parts.append(part)
        base = Path(*parts)
        candidates = [str(base)] if base.suffix else [
            str(base) + ext for ext in (".ts", ".tsx", ".js", ".jsx")
        ] + [str(base / ("index" + ext)) for ext in (".ts", ".tsx", ".js", ".jsx")]
    matches = [name for name in candidates if name in available]
    return matches[0] if len(matches) == 1 else None


def direct(root):
    from tree_sitter import Language, Parser

    parsers, nodes, edges, imports, calls, statuses = {}, [], [], [], [], {}
    paths = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    available = {p.relative_to(root).as_posix() for p in paths}
    for path in paths:
        name = path.relative_to(root).as_posix()
        nodes.append({"id": name, "kind": "file", "path": name})
        config = LANGUAGES.get(path.suffix)
        if config is None:
            statuses[name] = "unsupported"
            continue
        language, definitions, call_kinds, import_kinds = config
        if language not in parsers:
            package = "typescript" if language == "tsx" else language
            module = importlib.import_module("tree_sitter_" + package)
            factory = "language_" + language if language in ("typescript", "tsx", "php") else "language"
            parsers[language] = Parser(Language(getattr(module, factory)()))
        source = path.read_bytes()
        try:
            source.decode("utf-8")
        except UnicodeDecodeError:
            statuses[name] = "partial"
            continue
        tree = parsers[language].parse(source)
        statuses[name] = "partial" if tree.root_node.has_error else "parsed"
        for node in descendants(tree.root_node):
            if node.has_error:
                continue
            value = node.child_by_field_name("value") if node.type == "variable_declarator" else None
            arrow_definition = value is not None and value.type in ("arrow_function", "function_expression")
            if node.type in definitions.split() or arrow_definition:
                identifier = node.child_by_field_name("name")
                if identifier is None and node.type == "function_definition":
                    declarator = node.child_by_field_name("declarator")
                    if declarator is not None:
                        identifier = next((n for n in descendants(declarator) if n.type in ("identifier", "field_identifier")), None)
                if identifier is not None:
                    symbol_id = f"{name}:{node.start_byte}:{node.type}"
                    nodes.append({"id": symbol_id, "kind": node.type, "name": identifier.text.decode(),
                                  "path": name, "line": node.start_point.row + 1,
                                  "end_line": node.end_point.row + 1})
                    edges.append({"source": name, "target": symbol_id, "relation": "defines", "provenance": "parsed"})
            if node.type in call_kinds.split():
                calls.append({"path": name, "line": node.start_point.row + 1,
                              "expression": node.text.decode()[:160], "status": "unresolved"})
            if node.type in import_kinds.split() and language != "python":
                specifier_node = node.child_by_field_name("source")
                # An export declaration without a source is not a file dependency.
                if node.type == "export_statement" and specifier_node is None:
                    continue
                specifier = specifier_node.text.decode()[1:-1] if specifier_node else node.text.decode()
                target = relative_target(Path(name), specifier, available) if language in ("javascript", "typescript", "tsx") else None
                imports.append({"path": name, "line": node.start_point.row + 1, "specifier": specifier, "target": target})
        if language == "python" and statuses[name] == "parsed":
            try:
                python_tree = ast.parse(source)
            except (SyntaxError, ValueError):
                statuses[name] = "partial"
                continue
            for node in ast.walk(python_tree):
                if isinstance(node, (ast.ImportFrom, ast.Import)):
                    specifier = node.module or "" if isinstance(node, ast.ImportFrom) else node.names[0].name
                    level = node.level if isinstance(node, ast.ImportFrom) else 0
                    imports.append({"path": name, "line": node.lineno, "specifier": "." * level + specifier,
                                    "target": relative_target(Path(name), specifier, available, python=True, level=level)})
    for item in imports:
        if item["target"]:
            edges.append({"source": item["path"], "target": item["target"], "relation": "imports_file",
                          "line": item["line"], "provenance": "relative_path"})
    return {"nodes": nodes, "edges": edges, "imports": imports, "calls": calls, "statuses": statuses}


def graphify(root):
    from graphify.extract import extract

    paths = sorted(p for p in root.rglob("*") if p.suffix in LANGUAGES and p.is_file() and not p.is_symlink())
    # Explicit serial extraction avoids CPU-count-sized process pools. No CLI, LLM,
    # manifests, MCP config ingestion, language builds, or repository scripts.
    with contextlib.redirect_stdout(sys.stderr):
        return extract(paths, root=root, cache_root=Path("/tmp/cache"), parallel=False)


def summarize(graph):
    return {"nodes": len(graph["nodes"]), "edges": len(graph["edges"]),
            "relations": dict(Counter(e["relation"] for e in graph["edges"])),
            "json_bytes": len(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()),
            "unresolved_calls": len(graph.get("calls", [])),
            "file_statuses": dict(Counter(graph.get("statuses", {}).values())),
            "partial_files": sorted(p for p, status in graph.get("statuses", {}).items() if status == "partial"),
            "failed_sources": graph.get("failed_sources", [])}


def assertions(graph):
    ids = [node["id"] for node in graph["nodes"]]
    assert len(ids) == len(set(ids)), "symbol IDs must be distinct"
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])
    assert graph["statuses"]["safety/broken.py"] == "partial"
    assert not any(n.get("name") == "broken" for n in graph["nodes"])
    assert graph["statuses"]["safety/unsupported.unknown"] == "unsupported"
    pairs = {(e["source"], e["target"]) for e in graph["edges"] if e["relation"] == "imports_file"}
    for family, extension in (("python", "py"), ("typescript", "ts"), ("javascript", "js")):
        assert (f"{family}/use.{extension}", f"{family}/barrel.{extension}") in pairs
        assert (f"{family}/barrel.{extension}", f"{family}/target.{extension}") in pairs
    for family, extension in (("python", "py"), ("typescript", "ts")):
        assert (f"{family}/cycle_a.{extension}", f"{family}/cycle_b.{extension}") in pairs
        assert (f"{family}/cycle_b.{extension}", f"{family}/cycle_a.{extension}") in pairs
    assert all(call["status"] == "unresolved" for call in graph["calls"])
    for family in ("go", "rust", "java", "c", "cpp", "ruby", "csharp", "php", "bash"):
        names = {n.get("name") for n in graph["nodes"] if n["path"].startswith(family + "/")}
        assert {"helper", "entry"} <= names, (family, names)
    assert relative_target(Path("x/use.ts"), "./target", {"x/target.ts", "x/target.js"}) is None
    assert relative_target(Path("x/use.ts"), "../../outside", {"outside.ts"}) is None
    assert relative_target(Path("x/use.py"), "outside", {"outside.py"}, python=True, level=3) is None
    for path in ("typescript/component.tsx", "javascript/component.jsx"):
        assert any(n.get("name") == "Component" and n["path"] == path for n in graph["nodes"])


def evidence(graph):
    nodes = {n["id"]: n for n in graph["nodes"]}
    calls = [
        {"caller": nodes.get(e["source"], {}).get("label"),
         "target": nodes.get(e["target"], {}).get("label"),
         "target_file": nodes.get(e["target"], {}).get("source_file"),
         "source_file": e.get("source_file"), "line": e.get("source_location"),
         "confidence": e.get("confidence")}
        for e in graph["edges"] if e["relation"] in ("calls", "indirect_call")
    ]
    files = sorted({n.get("path", n.get("source_file")) for n in graph["nodes"]} - {None, ""})
    matrix = {}
    for family in sorted({name.split("/")[0] for name in files}):
        family_nodes = [n for n in graph["nodes"] if n.get("path", n.get("source_file", "")).startswith(family + "/")]
        matrix[family] = {"labels": sorted(n.get("name", n.get("label", "")) for n in family_nodes),
                          "calls": sum(c["source_file"].startswith(family + "/") for c in calls),
                          "unresolved_call_sites": sum(c["path"].startswith(family + "/") for c in graph.get("calls", [])),
                          "import_sites": sum(i["path"].startswith(family + "/") for i in graph.get("imports", [])),
                          "relations": dict(Counter(e["relation"] for e in graph["edges"]
                                                    if e.get("source_file", nodes.get(e["source"], {}).get("path", "")).startswith(family + "/")))}
    return {"summary": summarize(graph), "call_edges": calls, "matrix": matrix,
            "file_statuses": graph.get("statuses", {}),
            "imports": graph.get("imports", [])}


def probe(root, engine):
    """Compare clean full snapshots, including a change with unchanged callers."""
    import shutil

    working = Path("/tmp/probes")
    shutil.copytree(root, working)
    extractor = direct if engine == "direct" else graphify
    first = extractor(working)
    if engine == "direct":
        assertions(first)
    observations = {}
    observations["initial"] = evidence(first)
    if engine == "graphify":
        false_edge = next((e for e in observations["initial"]["call_edges"]
                           if e["caller"] == "shadow()" and e["target_file"] == "python/target.py"), None)
        assert false_edge and false_edge["confidence"] == "EXTRACTED", "recheck the pinned Graphify shadowing finding"
        observations["confirmed_false_shadow_call"] = false_edge
    before = hashlib.sha256((working / "python/use.py").read_bytes()).hexdigest()
    for family, extension in (("python", "py"), ("typescript", "ts"), ("javascript", "js")):
        (working / family / f"target.{extension}").unlink()
    deleted = extractor(working)
    if engine == "direct":
        assert not any(e["target"].endswith(("target.py", "target.ts", "target.js")) for e in deleted["edges"])
    observations["after_target_deletion"] = evidence(deleted)
    (working / "python/target.py").write_text("def replacement():\n    return 1\n")
    changed = extractor(working)
    if engine == "direct":
        assert not any(n.get("name") == "same" and n["path"] == "python/target.py" for n in changed["nodes"])
        assert any(e["source"] == "python/use.py" and e["target"] == "python/target.py" for e in changed["edges"])
    assert before == hashlib.sha256((working / "python/use.py").read_bytes()).hexdigest()
    observations["after_definition_change"] = evidence(changed)
    assert not Path("/tmp/CODE_GRAPH_REPO_EXECUTED").exists()
    observations["repository_execution_marker_absent"] = True
    observations["unchanged_caller_hash"] = before
    return observations


def cgroup_peak_bytes():
    for path in ("/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory/memory.max_usage_in_bytes"):
        try:
            return int(Path(path).read_text())
        except (OSError, ValueError):
            continue
    return None


if __name__ == "__main__":
    engine, mode = sys.argv[1:]
    started = time.monotonic()
    root = Path("/corpus")
    if mode == "probe":
        result = {"probe": probe(root, engine)}
    else:
        graph = (direct if engine == "direct" else graphify)(root)
        result = {"graph": summarize(graph)}
    result.update(engine=engine, seconds=round(time.monotonic() - started, 4),
                  process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                  cgroup_peak_bytes=cgroup_peak_bytes(),
                  python=platform.python_version(), machine=platform.machine(),
                  packages={d.metadata["Name"]: d.version for d in importlib.metadata.distributions()})
    print(json.dumps(result, sort_keys=True))
