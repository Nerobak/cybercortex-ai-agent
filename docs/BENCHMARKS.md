# Blind Benchmark Framework

The benchmark controller and research execution runtime have different trust
boundaries. During preflight, the trusted controller may parse private ground
truth to validate its integrity and compare it with agent-visible material for
contamination. These operations return fingerprints and contamination results,
not ground-truth objects. Research execution components receive only the public
`BenchmarkResearchInput` and an initializing `ResearchState`. The scorer may
receive the parsed ground truth only after research has terminated.

Strict-blind runs require a fresh, run-exclusive research database and a
run-scoped model-ledger baseline. Existing databases are not erased. Preflight
fails when the database contains another run, a prior revision, events, graph
assertions, or imports. A shared model ledger is allowed because benchmark
usage and cost are computed from the current run's baseline-to-final delta;
unrelated records remain intact and are excluded.

## Execution factory trust boundary

Execution factories are trusted operator code. Framework APIs pass them public
benchmark objects, and reviewed factories should return the documented public
research input, execution bindings, and reset plan. Factories execute as Python
in the same process and are **not a security sandbox**. A malicious factory can
independently inspect process arguments, files, environment variables, imported
modules, or framework internals. It could therefore bypass the accidental-
leakage protections provided by the normal framework APIs.

Strict benchmark validity requires a trusted, reviewed execution factory. The
framework does not claim to protect ground truth from malicious in-process
Python. Run untrusted code only inside an external isolation boundary chosen and
managed by the operator.
