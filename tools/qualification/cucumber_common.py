"""Cucumber leaf evidence: the corpus, the runtime, and the join between them.

WHY THIS EXISTS
---------------
The plan's largest family is CUCUMBER: 4,099 scenarios x 5 profiles = 20,495
rows, 89% of the denominator, all of them UNCOVERED. `run_leaf.py` cannot
move them: it reads libtest's per-case lines, and one libtest case runs an
ENTIRE feature file (122 scenarios in a single `test ... ok`). The leaf
granularity the plan asks for lives one level below libtest, inside the
cucumber writer's own output.

THE ONE HARD PROBLEM, AND WHAT IS DONE ABOUT IT
-----------------------------------------------
The catalogue names a Scenario Outline leaf by its TEMPLATE plus a position:

    Owns that have instances of type <value-type> cannot be unset [example 1/9]

The runtime prints the SUBSTITUTED name:

    Feature: Data validation :: Owns that have instances of type boolean cannot be unset

2,785 of the 4,099 catalogued scenarios are `[example i/N]` forms, so a
naive name join matches 15 of 725 on `owns-annotations.feature`. This module
closes that gap by RE-DERIVING the substitution the runtime performs, from
the same feature bytes, with the same algorithm - and then PROVING the
re-derivation three independent ways rather than assuming it:

  P1  CATALOGUE AGREEMENT. Expanding a feature file must reproduce the
      catalogue's `display_name` list for that feature EXACTLY - same names,
      same `[example i/N]` numbering, same order. The catalogue's own
      enumerator (tools/catalog/generate_catalog.py `cucumber_cases`) is a
      line-scanner; this one is a port of cucumber-0.19.1's real
      `expand_scenario`. Two independently written parsers agreeing leaf for
      leaf is evidence; either one alone is an assumption.
  P2  PLAN ANCHOR AGREEMENT. tools/catalog/build_plan_v2.py already anchors
      every cucumber leaf to `<file>:<declaration-line>[#exN]`. This module's
      expansion must reproduce that anchor for every leaf it claims. A leaf
      whose anchor disagrees is refused, never repaired.
  P3  RUNTIME SEQUENCE AGREEMENT. The ordered list of scenario names the
      runtime printed for a feature must equal, ELEMENT FOR ELEMENT, the
      ordered list of substituted names the expansion predicts (after
      removing the scenarios the runner's own ignore-tag filter excludes).
      Not a multiset, not a "mostly matches": the i-th printed scenario must
      be the i-th expanded example. Anything else refuses the feature.

Only when all three hold is a runtime scenario bound to a plan leaf. Per
template, the count of runtime scenarios must equal the count of runnable
`[example i/N]` rows the catalogue carries for it - that reconciliation is
computed and archived per template, and re-checked by the verifier.

THE SUBSTITUTION ALGORITHM IS A PORT, NOT AN INVENTION
------------------------------------------------------
`expand_examples` below follows cucumber-0.19.1
`src/feature.rs::expand_scenario` exactly:

  * placeholder regex `<([^>\\s]+)>` (no whitespace inside the brackets);
  * every `Examples:` block of a Scenario Outline contributes its table's
    rows after the header, in block order, flattened into ONE index space,
    which is what makes `[example i/N]` well defined across multiple blocks;
  * a block with no table, or a table with only a header, contributes
    nothing;
  * a placeholder with no matching header column is an EXPANSION ERROR - in
    cucumber it aborts the run, here it refuses the feature.

WHAT THE RUNTIME PRINTS, AND WHY IT IS READABLE AT ALL
------------------------------------------------------
`tests/behaviour/steps/lib.rs` installs a `SingletonParser` that rewrites
every scenario into its own one-scenario feature named
`<feature name> :: <scenario name>`. So cucumber's Basic writer emits exactly
one `Feature: <feature> :: <scenario>` line per executed scenario, and the
`[Summary]` block's feature count equals its scenario count. That line is the
leaf record; the `Scenario:` / `Scenario Outline:` line that follows it is
kept as a corroborating count.

TORN LINES ARE REAL AND ARE HANDLED WITHOUT LOOSENING ANYTHING
--------------------------------------------------------------
The archived logs were produced by libtest running many cases of one binary
CONCURRENTLY, all writing one stdout. `u2-full-1`'s `test_concept.log` line
7776 is:

    '   OK  Then entity(person) get owns is emptyFeature: Data validation :: Owns that have instances of type datetime cannot be unset'

- a step line and a feature line fused by two interleaved writes. Scanning
only at line starts silently LOSES that scenario (121 found where the
runtime's own summary says 122). So the scan looks for the marker anywhere in
a line, and accepts it only when what follows is one of the 47 CATALOGUED
FEATURE TITLES followed by ' :: '. The closed title set is what keeps this
from being a loosening: an arbitrary line containing the word "Feature:" is
not a scenario, and the P3 sequence check still has to pass afterwards.

OUTCOMES ARE READ, NEVER ASSUMED
--------------------------------
The only per-scenario outcome derivation this module admits:

  D1  ALL-PASSED SUMMARY. A cucumber `[Summary]` block reporting
      `K scenarios (K passed)` - zero skipped, zero failed, zero retried, no
      parsing errors, no hook errors - proves every scenario counted by that
      block passed. When every summary in a log is of that form AND their
      scenario counts sum to exactly the number of scenario lines scanned
      from that log, every scanned scenario passed.

When a log's summaries are NOT all-passed, this module publishes NOTHING for
that log and says why: with several libtest cases interleaving into one
stream, a failed step cannot be attributed to the scenario that owns it, so
which scenario failed is not derivable from those bytes. Guessing would be
the exact defect this program exists to prevent. Such a log is re-runnable
with `--test-threads 1`, which is stated in the refusal.
"""

import collections
import hashlib
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "catalog"))
import common  # noqa: E402
import leaf_common as lc  # noqa: E402

BH = REPO / "sources" / "typedb-behaviour"
TB = REPO / "sources" / "typedb"
BEHAVIOUR_ROOT = TB / "tests" / "behaviour"

SCHEMA = "typedb-r2-cucumber-leaf-evidence-v1"
RESULTS_NAME = "cucumber-leaf-results.json"
VERDICT_NAME = "cucumber-leaf-verdict.json"
MANIFEST_NAME = "bundle-manifest.json"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# cucumber-0.19.1 src/feature.rs: `Regex::new(r"<([^>\s]+)>")`
TEMPLATE_RE = re.compile(r"<([^>\s]+)>")

FEATURE_MARK = "Feature: "
TITLE_SEP = " :: "

# tests/behaviour/steps/lib.rs::is_ignore and
# tests/behaviour/service/http/http_steps/lib.rs::is_ignore_tag - the two
# scenario filters the two runners actually apply. A scenario carrying one of
# these tags is NEVER executed by that runner, so its leaf has no outcome and
# is reported NOT_RUN rather than quietly missing.
RUNNER_IGNORE_TAGS = {
    "native": frozenset({"ignore", "ignore-typedb"}),
    "http": frozenset({"ignore", "ignore-typedb-http"}),
}

GHERKIN_KEYWORD_RE = re.compile(
    r"^(Feature|Scenario Outline|Scenario Template|Scenario|Example|"
    r"Background|Examples|Scenarios|Rule)\s*:(.*)$")


def decolour(text):
    return ANSI_RE.sub("", text)


# --------------------------------------------------------------- the corpus

def _split_table_row(line):
    parts = line.strip().split("|")
    return [p.strip() for p in parts[1:-1]]


def parse_feature_file(path):
    """(feature title, [scenario]) from a .feature file.

    Deliberately a real lexer and not a line grep: docstrings (`\"\"\"`) can
    contain anything, including the word `Scenario:`, and a scanner that does
    not track them can invent or lose leaves. Tags are collected because the
    runners FILTER on them, comments are skipped, and each scenario records
    the 1-based line of its own declaration so the expansion can be checked
    against the plan's anchors.
    """
    lines = pathlib.Path(path).read_text().splitlines()
    title, scenarios, cur = None, [], None
    in_doc, doc_delim, pending_tags = False, None, []
    for i, raw in enumerate(lines):
        s = raw.strip()
        if in_doc:
            if s.startswith(doc_delim):
                in_doc = False
            continue
        if s.startswith('"""') or s.startswith("'''"):
            in_doc, doc_delim = True, s[:3]
            continue
        if not s or s.startswith("#"):
            continue
        if s.startswith("@"):
            pending_tags += [t[1:] for t in s.split() if t.startswith("@")]
            continue
        m = GHERKIN_KEYWORD_RE.match(s)
        if m:
            kw, rest = m.group(1), m.group(2).strip()
            if kw == "Feature":
                title, pending_tags = rest, []
            elif kw in ("Scenario Outline", "Scenario Template"):
                cur = {"kind": "outline", "name": rest, "tags": pending_tags,
                       "examples": [], "line": i + 1}
                scenarios.append(cur)
                pending_tags = []
            elif kw in ("Scenario", "Example"):
                cur = {"kind": "scenario", "name": rest, "tags": pending_tags,
                       "examples": [], "line": i + 1}
                scenarios.append(cur)
                pending_tags = []
            elif kw == "Background":
                cur, pending_tags = None, []
            else:  # Examples / Scenarios / Rule
                if kw in ("Examples", "Scenarios") and cur is not None \
                        and cur["kind"] == "outline":
                    cur["examples"].append({"tags": pending_tags, "rows": []})
                pending_tags = []
            continue
        if s.startswith("|") and cur is not None and cur["kind"] == "outline" \
                and cur["examples"]:
            cur["examples"][-1]["rows"].append(_split_table_row(s))
    return title, scenarios


def expand_examples(scn):
    """[(runtime_name, example_index, example_total)] or a substitution error.

    Port of cucumber-0.19.1 `expand_scenario`. Returns (rows, error) where
    error is the name of the first placeholder no Examples header supplies -
    in cucumber that aborts the run, so here it refuses the feature.
    """
    if scn["kind"] != "outline":
        return [(scn["name"], None, None)], None
    flat = []
    for ex in scn["examples"]:
        if len(ex["rows"]) < 2:
            continue  # no table, or header only: contributes nothing
        header, *vals = ex["rows"]
        for v in vals:
            flat.append((header, v))
    total, out, err = len(flat), [], None
    for idx, (header, v) in enumerate(flat):
        miss = []

        def repl(m, header=header, v=v, miss=miss):
            key = m.group(1)
            for k, val in zip(header, v):
                if k == key:
                    return val
            miss.append(key)
            return ""
        name = TEMPLATE_RE.sub(repl, scn["name"])
        if miss and err is None:
            err = miss[0]
        out.append((name, idx + 1, total))
    return out, err


def feature_entries(ref, path):
    """The full expansion of one feature file, in document order.

    Each entry is everything the join needs on the corpus side, in one place:
    the catalogue's display name, the name the RUNTIME will print, the
    outline template it came from, the plan anchor it must match, and the
    tags that decide whether a runner will run it at all.
    """
    title, scenarios = parse_feature_file(path)
    entries, errors = [], []
    for scn in scenarios:
        rows, err = expand_examples(scn)
        if err is not None:
            errors.append(
                f"{ref}:{scn['line']} Scenario Outline {scn['name']!r} uses "
                f"placeholder <{err}> which no Examples header supplies - "
                f"cucumber aborts on this, so the feature is refused")
            continue
        if scn["kind"] == "outline" and not rows:
            # every Examples row commented out upstream: expands to zero runs,
            # and generate_catalog.py deliberately puts no leaf in the plan
            continue
        for name, ex_i, ex_n in rows:
            entries.append({
                "ordinal": len(entries) + 1,
                "display_name": (f"{scn['name']} [example {ex_i}/{ex_n}]"
                                 if ex_i else scn["name"]),
                "runtime_name": name,
                "template": scn["name"] if ex_i else None,
                "kind": "OUTLINE_EXAMPLE" if ex_i else "SCENARIO",
                "declaration_line": scn["line"],
                "example_index": ex_i,
                "example_total": ex_n,
                "anchor": (f"{ref}:{scn['line']}#ex{ex_i}" if ex_i
                           else f"{ref}:{scn['line']}"),
                "tags": sorted(set(scn["tags"])),
            })
    return title, entries, errors


def build_corpus_index(catalog, plan, behaviour_root=BH):
    """{target_id: index} for every catalogued cucumber feature, with P1 and
    P2 decided per feature and recorded, never assumed.

    A feature whose expansion disagrees with the catalogue's leaf list, or
    with the plan's anchors, or whose bytes no longer hash to what the
    catalogue recorded, is marked unjoinable WITH THE REASON and contributes
    no leaf. Nothing is 'repaired' to make a join succeed.
    """
    by_target = collections.defaultdict(list)
    for leaf in catalog["leaf_cases"]:
        if leaf["kind"] == "CUCUMBER":
            by_target[leaf["target_id"]].append(leaf)
    targets = {t["target_id"]: t for t in catalog["targets"]}
    index = {}
    for tid, leaves in sorted(by_target.items()):
        ref = tid.split("cucumber-corpus:", 1)[1]
        path = pathlib.Path(behaviour_root) / ref
        rec = {"target_id": tid, "ref": ref, "feature_title": None,
               "source_path": str(path), "source_sha256": None,
               "catalogue_source_hash": None, "entries": [],
               "problems": [], "joinable": False}
        index[tid] = rec
        if not path.is_file():
            rec["problems"].append(
                f"feature file {ref} named by the catalogue is absent from the "
                f"pinned behaviour checkout - nothing can be joined to it")
            continue
        rec["source_sha256"] = common.sha256_file(path)
        declared = {sf["sha256"] for sf in targets.get(tid, {}).get("source_files", [])}
        rec["catalogue_source_hash"] = sorted(declared)
        if declared and rec["source_sha256"] not in declared:
            rec["problems"].append(
                f"{ref} now hashes {rec['source_sha256']} but the catalogue "
                f"target declares {sorted(declared)} - the corpus moved under "
                f"the denominator, so its scenarios are not the plan's")
            continue
        title, entries, errors = feature_entries(ref, path)
        rec["feature_title"] = title
        rec["problems"] += errors
        if errors:
            continue
        # ---- P1: the expansion must reproduce the catalogue leaf list
        mine = [e["display_name"] for e in entries]
        theirs = [l["display_name"] for l in leaves]
        if mine != theirs:
            first = next((k for k in range(max(len(mine), len(theirs)))
                          if mine[k:k + 1] != theirs[k:k + 1]), 0)
            rec["problems"].append(
                f"P1 FAILED for {ref}: the expansion yields {len(mine)} "
                f"scenario(s), the catalogue declares {len(theirs)}; first "
                f"divergence at position {first}: expansion says "
                f"{mine[first:first+1]}, catalogue says {theirs[first:first+1]}")
            continue
        # ---- P2: the expansion must reproduce the plan's own anchors
        anchor_bad = []
        for e, leaf in zip(entries, leaves):
            e["leaf_case_id"] = leaf["leaf_case_id"]
            pl = (plan.get("leaves") or {}).get(leaf["leaf_case_id"])
            if pl is None:
                anchor_bad.append(f"{leaf['leaf_case_id']} is not a plan leaf")
                continue
            e["fixture_set_id"] = pl.get("fixture_set_id", "fs:none")
            if pl.get("anchor") != e["anchor"]:
                anchor_bad.append(
                    f"{leaf['leaf_case_id']} anchors to {pl.get('anchor')!r} in "
                    f"the plan but the expansion places it at {e['anchor']!r}")
        if anchor_bad:
            rec["problems"].append(
                f"P2 FAILED for {ref}: {len(anchor_bad)} leaf/leaves disagree "
                f"with the plan's anchors, e.g. {anchor_bad[:3]}")
            continue
        rec["entries"] = entries
        rec["joinable"] = True
    return index


def runnable_entries(entries, runner):
    """The scenarios a runner will actually execute, and the ones its own tag
    filter removes. The filter is the runner's, not ours: see
    RUNNER_IGNORE_TAGS."""
    ign = RUNNER_IGNORE_TAGS[runner]
    run, skipped = [], []
    for e in entries:
        (skipped if ign & set(e["tags"]) else run).append(e)
    return run, skipped


# ---------------------------------------------------------- the cargo lane

CARGO_TEST_RE = re.compile(
    r"\[\[test\]\]\s*\n\s*path\s*=\s*\"([^\"]+)\"\s*\n\s*name\s*=\s*\"([^\"]+)\"")
FEATURE_PATH_RE = re.compile(
    r'"(?:\.\./typedb_behaviour\+/|bazel-typedb/external/typedb_behaviour\+*/)'
    r'([^"]+\.feature)"')


def cargo_behaviour_targets(cargo_toml=None):
    """{cargo target name: crate root path}, read from sources/typedb/Cargo.toml.

    Read, not executed. `cucumber_probe.discover_with_src_path()` asks cargo
    for the same fact, but asking cargo means a `--no-run` build, and this
    producer works from ARCHIVED logs precisely so it never needs one.
    Cargo.toml is the same declaration cargo itself reads.
    """
    text = pathlib.Path(cargo_toml or (TB / "Cargo.toml")).read_text()
    out = {}
    for path, name in CARGO_TEST_RE.findall(text):
        if path.startswith("tests/behaviour/"):
            out[name] = path
    return out


def runner_of(cargo_target, targets=None):
    """'http' or 'native' for a behaviour cargo target, or None.

    Decided by which Context the crate root lives under - everything below
    `tests/behaviour/service/http/` is the `http_steps` runner, whose ignore
    tag is `ignore-typedb-http`; everything else is the `steps` runner, whose
    ignore tag is `ignore-typedb`. This is not a guess about the file name:
    it is checked, because a log whose runner class were wrong would fail the
    P3 sequence check for any feature that carries either tag.
    """
    targets = targets if targets is not None else cargo_behaviour_targets()
    path = targets.get(cargo_target)
    if path is None:
        return None
    return "http" if path.startswith("tests/behaviour/service/http/") else "native"


MOD_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M)


def crate_files(root):
    """Every .rs file that belongs to the crate rooted at `root`.

    rustc's own rule, followed rather than approximated: a crate is its root
    file plus, transitively, the files its `mod name;` declarations name -
    `<dir>/name.rs` or `<dir>/name/mod.rs`, where `<dir>` is the declaring
    file's own module directory. Scoping by DIRECTORY instead would be wrong
    here and not subtly: `tests/behaviour/service/http/driver/` holds five
    separate one-file crates side by side, so a directory rule would tell
    every one of them that it runs all five driver features.
    """
    root = pathlib.Path(root).resolve()
    out, stack = [], [root]
    seen = set()
    while stack:
        f = stack.pop()
        if f in seen or not f.is_file():
            continue
        seen.add(f)
        text = f.read_text(errors="replace")
        out.append((f, text))
        base = f.parent if f.name in ("main.rs", "lib.rs", "mod.rs") \
            else f.parent / f.stem
        for name in MOD_RE.findall(text):
            for cand in (base / f"{name}.rs", base / name / "mod.rs"):
                if cand.is_file():
                    stack.append(cand.resolve())
                    break
    return out


def target_feature_refs(cargo_toml=None):
    """{cargo target: sorted feature refs the crate's own sources name}.

    Same fact `cucumber_probe.case_feature_map` derives, without the
    `cargo test --no-run` it needs: the crate roots come from Cargo.toml and
    the crate membership from `mod` declarations, so this producer never has
    to build anything to read an archive.
    """
    out = {}
    for name, path in sorted(cargo_behaviour_targets(cargo_toml).items()):
        refs = set()
        for _f, text in crate_files(TB / path):
            refs |= set(FEATURE_PATH_RE.findall(text))
        out[name] = sorted(refs)
    return out


# --------------------------------------------------------------- the runtime

SUMMARY_STATS_RE = re.compile(
    r"^(?P<total>\d+) (?P<what>features?|scenarios?|steps?|rules?)"
    r"(?: \((?P<detail>[^)]*)\))?\s*$")
STAT_ITEM_RE = re.compile(r"^(\d+) (passed|skipped|failed)$")
RETRY_RE = re.compile(r"^(\d+) retr(?:y|ies)$")


def _parse_stats(detail):
    """cucumber Styles::format_stats, read backwards. Returns
    (dict, problems)."""
    got = {"passed": 0, "skipped": 0, "failed": 0, "retried": 0}
    problems = []
    if not detail:
        return got, problems
    body, _, retry = detail.partition(" with ")
    if retry:
        m = RETRY_RE.match(retry.strip())
        if not m:
            problems.append(f"unparsable retry clause {retry!r}")
        else:
            got["retried"] = int(m.group(1))
    for item in body.split(", "):
        m = STAT_ITEM_RE.match(item.strip())
        if not m:
            problems.append(f"unparsable stat item {item!r}")
            continue
        got[m.group(2)] = int(m.group(1))
    return got, problems


def parse_summaries(text):
    """Every cucumber `[Summary]` block in a log, with its line number.

    Shape follows cucumber-0.19.1 `Styles::summary`:
        [Summary] / N features / [M rules] / K scenarios (stats) /
        S steps (stats) / [parsing errors][, ][hook errors]
    Anything that does not read back in that shape is a problem on the block,
    and a block with problems refuses the log rather than being skipped.
    """
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        if line.strip() != "[Summary]":
            continue
        block = {"line": i + 1, "features": None, "rules": 0,
                 "scenarios": None, "scenario_stats": None,
                 "steps": None, "step_stats": None,
                 "parsing_errors": 0, "hook_errors": 0, "problems": [],
                 "raw": []}
        j = i + 1
        while j < len(lines) and j <= i + 6:
            s = lines[j].strip()
            if not s:
                break
            m = SUMMARY_STATS_RE.match(s)
            if m:
                block["raw"].append(s)
                stats, probs = _parse_stats(m.group("detail"))
                block["problems"] += probs
                what = m.group("what").rstrip("s")
                n = int(m.group("total"))
                if what == "feature":
                    block["features"] = n
                elif what == "rule":
                    block["rules"] = n
                elif what == "scenario":
                    block["scenarios"], block["scenario_stats"] = n, stats
                elif what == "step":
                    block["steps"], block["step_stats"] = n, stats
                j += 1
                continue
            m2 = re.match(r"^(\d+) parsing errors?$", s)
            if m2:
                block["parsing_errors"] = int(m2.group(1))
                block["raw"].append(s)
                j += 1
                continue
            m3 = re.match(r"^(\d+) hook errors?$", s)
            if m3:
                block["hook_errors"] = int(m3.group(1))
                block["raw"].append(s)
                j += 1
                continue
            break
        if block["features"] is None or block["scenarios"] is None \
                or block["steps"] is None:
            block["problems"].append(
                f"the [Summary] block at line {block['line']} is missing its "
                f"feature, scenario or step line - the block is truncated and "
                f"cannot vouch for any outcome")
        out.append(block)
    return out


def all_passed(block):
    """D1: does this block prove every scenario it counted passed?"""
    st = block.get("scenario_stats") or {}
    return (not block["problems"]
            and block.get("scenarios") is not None
            and st.get("passed") == block["scenarios"]
            and st.get("skipped") == 0 and st.get("failed") == 0
            and st.get("retried") == 0
            and block.get("parsing_errors") == 0
            and block.get("hook_errors") == 0)


def scan_scenario_lines(text, titles):
    """[(line_no, column, feature_title, scenario_name)] for every scenario the
    runtime announced, tolerant of interleaved (torn) writes.

    `titles` is the CLOSED set of catalogued feature titles. The marker is
    accepted anywhere in a line, but only when followed by one of those titles
    and ' :: ' - see the module docstring for the real torn line this exists
    for. Longest title first, so a title that is a prefix of another cannot
    steal the match.
    """
    ordered = sorted(titles, key=len, reverse=True)
    out, unattributed = [], []
    for ln, line in enumerate(text.splitlines(), start=1):
        idx = 0
        while True:
            j = line.find(FEATURE_MARK, idx)
            if j < 0:
                break
            rest = line[j + len(FEATURE_MARK):]
            for t in ordered:
                if rest.startswith(t + TITLE_SEP):
                    out.append((ln, j + 1, t, rest[len(t) + len(TITLE_SEP):]))
                    break
            else:
                unattributed.append((ln, j + 1, rest[:120]))
            idx = j + 1
    return out, unattributed


def count_keyword_lines(text):
    """(plain Scenario: lines, Scenario Outline: lines) - the corroborating
    count. The Basic writer prints exactly one of these per executed scenario,
    and which keyword it prints says whether the scenario came from an outline,
    which is a fact the expansion also predicts."""
    plain = outline = 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Scenario Outline:") or s.startswith("Scenario Template:"):
            outline += 1
        elif s.startswith("Scenario:") or s.startswith("Example:"):
            plain += 1
    return plain, outline


def join_reconciliation(corpus, features, leaves):
    """The headline the whole exercise turns on, in numbers a reader can check.

    Aggregated from the SAME per-feature records the verifier recomputes, so
    it is a summary of proven facts and not a second, softer claim. The
    `identical_substituted_name_*` figures are here because they are the
    reason the ordinal binding exists at all: when nine examples of one
    template substitute to the same string, a name-based join cannot tell
    them apart and only position can.
    """
    templates, ident_groups, ident_rows = set(), 0, 0
    ex_catalogued = plain_catalogued = 0
    for rec in corpus.values():
        if not rec.get("joinable"):
            continue
        seen = collections.Counter()
        for e in rec["entries"]:
            if e["template"] is None:
                plain_catalogued += 1
                continue
            ex_catalogued += 1
            templates.add((rec["target_id"], e["template"], e["declaration_line"]))
            seen[(e["template"], e["declaration_line"], e["runtime_name"])] += 1
        for _k, n in seen.items():
            if n > 1:
                ident_groups += 1
                ident_rows += n
    return {
        "features_expanded": sum(1 for r in corpus.values() if r.get("joinable")),
        "scenarios_expanded": sum(len(r["entries"]) for r in corpus.values()),
        "P1_features_agreeing_with_catalogue":
            sum(1 for r in corpus.values() if r.get("joinable")),
        "P2_leaves_agreeing_with_plan_anchor":
            sum(len(r["entries"]) for r in corpus.values() if r.get("joinable")),
        "P3_features_order_exact_in_owning_log":
            sum(1 for f in features if f.get("owner")),
        "outline_templates": len(templates),
        "outline_examples_catalogued": ex_catalogued,
        "plain_scenarios_catalogued": plain_catalogued,
        "outline_examples_bound": sum(1 for l in leaves if l["example_index"]),
        "plain_scenarios_bound": sum(1 for l in leaves if not l["example_index"]),
        "scenarios_bound_total": len(leaves),
        "features_refused": sum(1 for f in features if f.get("refusals")),
        "identical_substituted_name_groups": ident_groups,
        "identical_substituted_name_scenarios": ident_rows,
    }


# ------------------------------------------------------------- bundle seal

def bundle_files(results_dir, bundle, repo=REPO):
    """Every file this bundle's claims rest on: its own results file, and
    every archived log it read - including logs that live inside the SEALED
    leaf bundles this producer derives from. Those logs are referenced, never
    copied: a copy is a second artefact that can drift from the original,
    while a reference hashed into this bundle's root binds the two together."""
    results_dir = pathlib.Path(results_dir)
    files = [results_dir / RESULTS_NAME]
    for s in bundle.get("sources", []):
        for l in s.get("logs", []):
            p = pathlib.Path(l["raw_log"])
            files.append(p if p.is_absolute() else pathlib.Path(repo) / p)
    return files


def compute_bundle_root(results_dir, bundle, repo=REPO):
    """Identical algorithm to leaf_common.compute_bundle_root and
    verdict.compute_bundle_root: sha256 of `rel \\0 sha \\n` over sorted
    repo-relative paths. Every seal in this repository is recomputed the same
    way, over whatever set of files that seal covers."""
    repo = pathlib.Path(repo)
    pairs = {}
    for f in bundle_files(results_dir, bundle, repo):
        if f.is_file():
            try:
                rel = f.resolve().relative_to(repo.resolve()).as_posix()
            except ValueError:
                rel = str(f.resolve())
            pairs[rel] = common.sha256_file(f)
    h = hashlib.sha256()
    for rel in sorted(pairs):
        h.update(rel.encode() + b"\0" + pairs[rel].encode() + b"\n")
    return h.hexdigest(), pairs
