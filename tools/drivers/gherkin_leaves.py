#!/usr/bin/env python3
"""Independent Gherkin leaf enumerator for the official-driver lane.

Why a second parser exists: the driver-lane runner must be able to say, for
one feature file, EXACTLY which leaf cases the qualification plan expects and
EXACTLY what name each of them will print when cucumber runs it. Reusing
tools/catalog/generate_catalog.py for that would let one parser vouch for
itself. This module reimplements the enumeration from the feature-file BYTES
and the runner then requires that its leaf-id list equals the plan's leaf-id
list for the same file, byte-anchored by the plan's recorded source hash.
Two disagreeing parsers stop the line - the same rule completeness.py uses.

What a leaf is (identical scheme to the catalogue, re-derived here):

  Scenario:           -> one leaf, id `cucumber:<ref>::<name>`
  Scenario Outline:   -> one leaf PER Examples data row, in file order,
                         id `cucumber:<ref>::<name>#ex<N>`
  duplicate ids       -> the second and later occurrences carry `@2`, `@3`...

What this module adds on top of the catalogue's enumeration, because the
runner needs it to JOIN observed cucumber output onto plan leaves:

  * `display_name` - the name cucumber will PRINT. For an outline example
    that is the outline name with every `<column>` placeholder replaced by
    that row's value, which is what cucumber-rs 0.19 expands scenarios to.
  * `tags` - feature-level + scenario-level + Examples-level tags, so a leaf
    the runner's driver skips by tag is recorded as SKIPPED_IGNORED naming
    the exact tag, never silently dropped from the denominator.
  * `line` - the scenario's declaration line (1-based).

Fail-closed behaviours: a `Rule:` keyword raises (the upstream
SingletonParser in rust/tests/behaviour/steps/lib.rs takes only
`feature.scenarios` and would silently drop rule-nested scenarios, so a
corpus that grew one must stop this runner, not be half-executed); an
Examples block whose data row has a different column count than its header
raises; a placeholder with no matching column raises.
"""
import pathlib
import re
import sys

SCENARIO_RE = re.compile(r"^(Scenario Outline|Scenario Template|Scenario|Example):\s*(.*)$")
EXAMPLES_RE = re.compile(r"^(Examples|Scenarios):\s*(.*)$")
KEYWORD_BREAK_RE = re.compile(r"^(Scenario|Scenario Outline|Scenario Template|Example|Feature|Rule|Background)\b")
TAG_RE = re.compile(r"^@\S")


class GherkinError(Exception):
    pass


def _split_row(line):
    # `| a | b |` -> ["a", "b"]; escaped pipes are not used by this corpus and
    # are rejected rather than guessed at.
    if "\\|" in line:
        raise GherkinError(f"escaped pipe in table row is not supported: {line!r}")
    parts = line.split("|")
    if len(parts) < 3 or parts[0].strip() or parts[-1].strip():
        raise GherkinError(f"malformed table row: {line!r}")
    return [p.strip() for p in parts[1:-1]]


def enumerate_leaves(feature_path, ref):
    """-> list of dicts, in execution order.

    Each dict: {leaf_case_id, base_id, display_name, kind, line, tags,
                example_index, example_count}
    """
    text = pathlib.Path(feature_path).read_text()
    lines = text.splitlines()

    if any(re.match(r"^\s*Rule:", ln) for ln in lines):
        raise GherkinError(
            f"{ref}: contains a `Rule:` block; the upstream SingletonParser "
            f"consumes only feature.scenarios and would silently skip "
            f"rule-nested scenarios - refusing to enumerate")

    feature_tags = []
    seen_feature = False
    pending_tags = []
    scenarios = []      # raw scenario records
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        s = raw.strip()
        if not s or s.startswith("#"):
            i += 1
            continue
        if TAG_RE.match(s):
            pending_tags.extend(t for t in s.split() if t.startswith("@"))
            i += 1
            continue
        if s.startswith("Feature:"):
            if not seen_feature:
                feature_tags = list(pending_tags)
                seen_feature = True
            pending_tags = []
            i += 1
            continue
        m = SCENARIO_RE.match(s)
        if m:
            keyword, name = m.group(1), m.group(2).strip()
            rec = {"keyword": keyword, "name": name, "line": i + 1,
                   "tags": feature_tags + pending_tags, "examples": []}
            pending_tags = []
            j = i + 1
            block = None          # {"tags": [...], "header": [...], "rows": [...]}
            block_tags = []
            while j < n:
                l2 = lines[j].strip()
                if not l2 or l2.startswith("#"):
                    j += 1
                    continue
                if TAG_RE.match(l2):
                    block_tags.extend(t for t in l2.split() if t.startswith("@"))
                    j += 1
                    continue
                if KEYWORD_BREAK_RE.match(l2):
                    break
                me = EXAMPLES_RE.match(l2)
                if me:
                    block = {"tags": list(block_tags), "header": None, "rows": []}
                    rec["examples"].append(block)
                    block_tags = []
                    j += 1
                    continue
                if l2.startswith("|") and block is not None:
                    row = _split_row(l2)
                    if block["header"] is None:
                        block["header"] = row
                    else:
                        if len(row) != len(block["header"]):
                            raise GherkinError(
                                f"{ref}:{j + 1}: Examples row has {len(row)} cells "
                                f"but the header has {len(block['header'])}")
                        block["rows"].append(row)
                    j += 1
                    continue
                # any other content (step, docstring, data table of a step)
                block = None
                block_tags = []
                j += 1
            scenarios.append(rec)
            # The tag block that belongs to the NEXT scenario sits inside the
            # window this inner scan just walked. Hand those lines back to the
            # outer loop, or the next scenario silently loses its tags - which
            # is exactly how a @ignore-... scenario would be counted as
            # runnable and then reported NOT_RUN. (Executed proof: before this
            # fix, driver/connection.feature reported 0 tagged scenarios while
            # carrying two @ignore-typedb-http ones.)
            i = _rewind_to_tag_block(lines, j)
            continue
        pending_tags = []
        i += 1

    leaves = []
    seen = {}

    def uniq(base):
        k = seen.get(base, 0) + 1
        seen[base] = k
        return base if k == 1 else f"{base}@{k}"

    for rec in scenarios:
        is_outline = rec["keyword"] in ("Scenario Outline", "Scenario Template")
        rows = [(blk, r) for blk in rec["examples"] for r in blk["rows"]]
        if not is_outline:
            if rows:
                raise GherkinError(
                    f"{ref}:{rec['line']}: plain `{rec['keyword']}:` carries an "
                    f"Examples block")
            base = f"cucumber:{ref}::{rec['name']}"
            leaves.append({
                "leaf_case_id": uniq(base), "base_id": base,
                "display_name": rec["name"], "kind": "SCENARIO",
                "line": rec["line"], "tags": list(rec["tags"]),
                "example_index": None, "example_count": None,
            })
            continue
        if not rows:
            # dead outline (all Examples rows commented out): zero leaves,
            # exactly as the catalogue records it
            continue
        total = len(rows)
        for idx, (blk, row) in enumerate(rows, start=1):
            mapping = dict(zip(blk["header"], row))
            display = _substitute(rec["name"], mapping, ref, rec["line"])
            base = f"cucumber:{ref}::{rec['name']}#ex{idx}"
            leaves.append({
                "leaf_case_id": uniq(base), "base_id": base,
                "display_name": display, "kind": "OUTLINE_EXAMPLE",
                "line": rec["line"], "tags": rec["tags"] + blk["tags"],
                "example_index": idx, "example_count": total,
            })
    return leaves


def _rewind_to_tag_block(lines, j):
    """Given the index the inner scan stopped at (a keyword line or EOF),
    return the index of the first line of the contiguous tag block that
    immediately precedes it, or `j` when there is none."""
    k = j - 1
    while k >= 0 and (not lines[k].strip() or lines[k].strip().startswith("#")):
        k -= 1
    if k < 0 or not TAG_RE.match(lines[k].strip()):
        return j
    while k - 1 >= 0:
        prev = lines[k - 1].strip()
        if TAG_RE.match(prev):
            k -= 1
        elif not prev or prev.startswith("#"):
            # blank/comment lines inside a tag block keep it contiguous only
            # if another tag line precedes them
            m = k - 1
            while m >= 0 and (not lines[m].strip()
                              or lines[m].strip().startswith("#")):
                m -= 1
            if m >= 0 and TAG_RE.match(lines[m].strip()):
                k = m
            else:
                break
        else:
            break
    return k


def _substitute(name, mapping, ref, line):
    out = []
    pos = 0
    for m in re.finditer(r"<([^<>]+)>", name):
        key = m.group(1)
        if key not in mapping:
            raise GherkinError(
                f"{ref}:{line}: outline name references <{key}> which is not an "
                f"Examples column ({sorted(mapping)})")
        out.append(name[pos:m.start()])
        out.append(mapping[key])
        pos = m.end()
    out.append(name[pos:])
    return "".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: gherkin_leaves.py <feature-file> <ref>", file=sys.stderr)
        raise SystemExit(2)
    for lf in enumerate_leaves(sys.argv[1], sys.argv[2]):
        print(lf["leaf_case_id"], "|", lf["display_name"], "|", ",".join(lf["tags"]))
