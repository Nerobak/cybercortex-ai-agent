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

## Blind GraphQL authorization fixture

`agent_core.benchmark.graphql_lab` defines the P4-1I.1 controlled local ASGI
fixture and its trusted execution factory. The public target is only the origin;
the GraphQL route, schema, operation, argument, and opaque object values are not
part of `BenchmarkResearchInput`. The route is discoverable from ordinary HTML,
JavaScript, and OpenAPI metadata. Introspection is intentionally enabled and is
treated as semantic discovery evidence, never as a vulnerability.

The fixture has two controlled identities and one opaque test-owned resource per
identity. Credentials enter research only as process-local vault references.
Object references are acquired from an owner-scoped read-only collection rather
than pre-seeded in the initial `ResearchState`. The target is read-only from the
research boundary and exposes a controller-side deterministic reset that restores
identities, tokens, resources, ownership, and request-visible state. Its health
response contains only availability status.

The 32-request ceiling is derived as follows: 12 requests for ordinary discovery,
8 for GraphQL semantic/authenticated discovery and owner-scoped object
acquisition, 4 for an initial vulnerable and secure-control differential, 2 for
independent reproduction, and a 6-request bounded reserve for normal discovery
variation. The strategy architecture is limited to 6 lightweight model calls,
4 experiments, 2 reproductions, no chain experiments, and 180 seconds. Private
truth contains one read-only GraphQL object-authorization finding. Correctly
enforced authentication and protected-field behavior are diagnostic controls,
not ground-truth findings.

P4-1I.1 constructs and tests this fixture only. It does not run CyberCortex
against the target and does not invoke any model provider.
