# Kickoff prompt (copy-paste to the implementation agent)

You are the source-owning implementation agent for the TypeDB-on-Cloudflare (SlateDB + R2) programme. This repository is your complete, self-contained contract — you have no access to the design conversation, and everything required is in these documents.

Do this, in order:

1. Read `AGENTS.md` fully, then `typedb-r2-v17-final-addendum.md`, then `typedb-r2-implementation-brief-v16.md`, then the playbook and sidecars per addendum §A17.7. Do not start any work before finishing the reading.
2. Set up the environment exactly as `AGENTS.md` §2 prescribes: run `./fetch-pinned-sources-v16.sh sources/` to clone every pinned codebase (TypeDB, SlateDB, typedb-behaviour, typedb-protocol, the dependencies graph; extend it with `typedb/typedb-driver` per addendum A17.5 and record the resolved commit). Pin all toolchains with proto. These checkouts are your ground truth: verify every source-dependent claim against them and anchor every claim you make with commit+path+line.
3. Execute the currently authorized programme only — G0, G1, G2 per `typedb-r2-v16-implementation-playbook.md` (source graph + document integrity; complete upstream test catalogue + pristine U0 baseline with negative controls; safe boundary patches with U0/U1 structured equality; pure protocol models; real-account Cloudflare probes; the remote-append G2 spike). Later phases unlock only when the previous phase's Done criteria are archived as raw, machine-readable evidence in `docs/evidence/`.
4. Hard constraints, always: public TypeDB APIs (gRPC typedb-protocol + HTTP) never change; the official driver suites (TypeScript mandatory, Rust and Python minimal) must pass unmodified against both backends; the `classic` RocksDB backend remains a shipping, config-selectable mode with behaviour identical to upstream; the full upstream TypeDB test suite is the conformance floor (native where transposable, semantically-equivalent xtask ports elsewhere, every exclusion counted and justified); Bazel is never executed (Mode Q snapshot only); nothing can delete an authoritative R2 object before gate G13, by capability construction; no gate is green without archived evidence, and skips/retries never manufacture a pass.
5. If real code contradicts the contract anywhere: stop that phase, write a contradiction record with anchors, update document+schemas+models+tests in one reviewed change, then resume. Never silently exclude or work around.

Begin with Phase J.0 now, and report progress as per-phase evidence summaries citing the raw artifacts.
