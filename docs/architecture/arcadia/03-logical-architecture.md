# 3 — Logical Architecture

**Arcadia level:** LA. **Maturity: PROVISIONAL.** Technology-free decomposition of *how* the
system delivers its functions. Read the status marker on each component: the conformance
components exist and are measured; the storage components are a design intent that has not
been built.

## Logical components

```
┌──────────────────────────────────────────────────────────────────┐
│ LC-1 Query & Type Engine                          [EXISTS]       │
│      schema, type inference, query planning, execution           │
└───────────────────────┬──────────────────────────────────────────┘
                        │ LI-1  storage abstraction
┌───────────────────────▼──────────────────────────────────────────┐
│ LC-2 Storage Abstraction                          [EXISTS]       │
│      keyspaces, snapshots, iterators, commit, WAL                │
└───────────────────────┬──────────────────────────────────────────┘
                        │ LI-2  engine binding  ◀── the seam
        ┌───────────────┴───────────────┐
┌───────▼─────────────┐       ┌─────────▼──────────────────────────┐
│ LC-3a Local-Disk    │       │ LC-3b Object-Store Engine          │
│       Engine        │       │                        [INTENDED]  │
│            [EXISTS] │       └─────────┬──────────────────────────┘
└─────────────────────┘                 │ LI-3  object protocol
                                ┌───────▼──────────────────────────┐
                                │ LC-4 Object Store    [EXTERNAL]  │
                                └──────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ LC-5 Lifecycle Manager                            [INTENDED]     │
│      start on demand, quiesce, resume                            │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ Conformance subsystem                             [EXISTS]       │
│  LC-6 Corpus Enumerator ─▶ LC-7 Execution Harness ─▶ LC-8 Verdict│
└──────────────────────────────────────────────────────────────────┘
```

## Components

### LC-1 Query & Type Engine — *exists, unchanged*

Owns SF-1/SF-3. **The programme's premise is that this component is not modified.** Every
behaviour scenario in the corpus is, in effect, a test of LC-1 through LI-1.

### LC-2 Storage Abstraction — *exists*

Owns SF-2/SF-4/SF-5 at the logical level. Its interface to LC-1 (LI-1) is what must stay
semantically fixed. Whether its *internals* need to change to accommodate LC-3b is an open
question and the main unknown at this level — see "What is not yet decided".

### LC-3a / LC-3b — the substitution

The entire programme is: keep LI-2's contract, swap the component behind it. LC-3a is
local-disk with POSIX durability; LC-3b persists to an object store.

**These are not behaviourally equivalent**, and the logical model should not pretend they are:

| Property | LC-3a | LC-3b |
|---|---|---|
| Durability point | `fsync` | acknowledged object write |
| Latency | microseconds | milliseconds |
| Atomic rename | yes | no |
| Failure modes | disk | network partition, throttling, partial visibility |

The claim under test is not "the engines behave identically" — it is "**the system's observable
behaviour through LI-1 is identical**". That is a strictly weaker and actually achievable
claim, and stating it precisely is the difference between a provable goal and a slogan.

### LC-5 Lifecycle Manager — *intended*

Owns SF-6. Must guarantee that quiescing is indistinguishable from continuous operation, given
LC-3b's durability point. Not designed.

### LC-6/7/8 Conformance subsystem — *exists and measured*

* **LC-6 Corpus Enumerator** — derives the denominator from pinned sources: BUILD-declared
  targets, Cucumber scenarios expanded per `Examples` row, failpoints crossed with loop
  contexts, libtest cases read off built harnesses. Fails on anything it cannot parse.
* **LC-7 Execution Harness** — runs each target, attributes results to leaf cases, enforces
  timeouts, refuses filtering environments.
* **LC-8 Verdict** — reconciles executed against catalogued; green requires full accounting.

Why these are logical components rather than tooling: they realise SF-8/9/10, which realise
OC-5. See [ADR-0003](../ADR/0003-conformance-runner-no-false-green.md).

## Logical interfaces

| ID | Between | Contract | Status |
|---|---|---|---|
| LI-1 | LC-1 ↔ LC-2 | snapshots, iterators, commit; **semantics frozen** | exists |
| LI-2 | LC-2 ↔ LC-3x | the substitution seam | exists; LC-3b binding not built |
| LI-3 | LC-3b ↔ LC-4 | object get/put/list/delete | not built |
| LI-4 | LC-6 → LC-7 | the catalogue: 258 targets, 4 757 leaf cases | exists, schema-validated |
| LI-5 | LC-7 → LC-8 | per-case outcomes | exists |

## What is not yet decided

Stated as open questions rather than glossed:

1. **Does LI-2 survive unchanged?** LC-2's interface was shaped around an engine with cheap
   `fsync` and atomic rename. Whether LC-3b can satisfy it as-written, or whether LI-2 must
   widen (e.g. explicit async durability), is unknown until attempted.
2. **Where does the WAL live?** LC-2 owns a WAL today. Object stores are a poor fit for
   record-at-a-time appends, and LC-3b has its own WAL. Two WALs in series is likely wrong;
   which one survives is undecided.
3. **What is the durability acknowledgement point?** Fixing this determines whether SF-2's
   obligation is met, and it is the question the two `todo!()` upstream tests would have
   helped answer.
4. **Does LC-5 need to participate in durability?** If quiescing can occur mid-transaction,
   lifecycle and storage are coupled rather than independent.

Question 2 is the one most likely to force a change to LC-2's internals, and therefore the
first thing to prototype.

## Traceability

| System function | Logical components |
|---|---|
| SF-1, SF-3 | LC-1 |
| SF-2, SF-4, SF-5 | LC-2 → LC-3x → LC-4 |
| SF-6 | LC-5, LC-2 |
| SF-7 | LC-1 |
| SF-8 | LC-6 |
| SF-9 | LC-7 |
| SF-10 | LC-8 |
