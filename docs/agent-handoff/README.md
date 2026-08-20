# Agent handoff

Durable, on-disk context for a session that starts with **zero** memory of
what came before. Conversations end; this directory is what survives them.

## Rules for this directory

1. **One document per handoff**, named `YYYY-MM-DD-<from>-to-<to>.md`.
2. **Write for a reader with no context.** Do not say "as discussed" or
   "the usual gate" — name the file, the command, the number.
3. **Every claim carries the command that reproduces it.** A number without
   a command is a rumour.
4. **Record what is red as carefully as what is green**, and separate
   *blocked by the machine* from *blocked by unwritten product code* from
   *blocked upstream*. Those have different owners and different fixes.
5. **Record the traps.** Things that cost hours are worth three lines.
6. Supersede, never silently rewrite: a later handoff may correct an
   earlier one, but says so.

## Current

| Date | Handoff | Read this if |
|---|---|---|
| 2026-08-20 | [`2026-08-20-round6-to-round7.md`](2026-08-20-round6-to-round7.md) | you are starting any new session on this repository |

## Related durable context

- `AGENTS.md` — the enforceable quality contract (short, root).
- `.quality/agents/*.md` — the seven role contracts.
- `docs/ledger/gates.json` — the machine-readable truth plane. **The
  authority.** `docs/operations.md` is *rendered* from it, never edited.
- `docs/owner-decisions.json` — decisions an implementation may not invent.
- `contract/` — the normative brief and addendum. Outranks everything above.
