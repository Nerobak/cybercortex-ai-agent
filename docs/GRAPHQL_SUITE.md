# GraphQL Security Suite (v2.1 Phase 1)

## Purpose and architecture

The GraphQL suite adds evidence-driven surface analysis to the stable v2 core through five normal registry tools: endpoint discovery, offline query analysis, offline schema analysis, opt-in introspection checking, and manual authorization planning. It does not replace the workflow manager, runner, normalizer, finding schema, scope guard, CLI framework, or reporting fallback.

The automatic evidence flow is `katana_crawl` → normalized surface → endpoint discovery → applicable offline analyzers → optional introspection → controlled authorization planning. A stage reports `not_applicable` or `skipped` with a reason when its input is absent. Optional GraphQL stages do not reduce required scan coverage.

## Default-safe behavior

- Every candidate URL and every active request must pass configured domain and URL-prefix scope.
- Endpoint discovery is offline in automatic scans. Common-route generation is disabled unless explicitly requested by a caller.
- Query and schema inputs are analyzed offline and are never executed.
- Mutations, subscriptions, batching, aliases, recursive amplification, denial-of-service queries, authentication bypass payloads, retries, and destructive operations are never sent.
- Authorization tooling produces plans only. `automatic_execution` is always false.
- DeepSeek may explain deterministic evidence, but the normalizer controls observation, candidate, and verified classifications.

## Configuration

```dotenv
GRAPHQL_INTROSPECTION_ENABLED=false
GRAPHQL_TIMEOUT_SECONDS=15
GRAPHQL_MAX_RESPONSE_BYTES=1000000
```

Introspection requires a `deep` or `authenticated` profile, an explicit true setting, and a confirmed or high-confidence endpoint. It sends one standard bounded POST request with no aliases, batching, mutation, recursion, or retry. Redirect destinations are scope-checked, response bytes are bounded, and credential- or secret-named response values are redacted.

## Endpoint confidence model

- `confirmed`: GraphQL content type, formatted response/schema evidence, or explicit GraphQL client configuration.
- `likely`: GraphQL error or operation/query/variables evidence supports the endpoint.
- `possible`: reserved for weak combined evidence.
- `route_name_only`: only a route such as `/graphql` or `/gql` was observed.

A string containing “graphql,” especially in a static asset, does not confirm an endpoint. All endpoint records remain observations and state whether a network check occurred.

## Introspection limitations

Introspection availability is never a candidate or verified finding by itself. The report wording is: “GraphQL introspection was available on the tested endpoint. This may aid schema discovery but does not by itself establish a security vulnerability.” Raw schemas are not shown on the dashboard by default.

## Offline examples

```text
graphql analyze ./evidence/query.graphql
graphql schema ./evidence/introspection.json
graphql explain
explain graphql_introspection_checker
```

The schema analyzer reports full counts but limits samples to 25 operations per category and 50 representative fields, with deterministic truncation flags.

## Authorization planning and safety boundaries

Planning requires a confirmed/high-confidence endpoint, analyzed operations, and metadata for at least two researcher-controlled accounts. Object tests use only test-owned identifiers. Field comparisons check secure omission, denial, nulling, or redaction. Mutation plans require reversible actions on test-owned objects and before/after evidence.

Stop immediately if third-party data appears, ownership or scope is uncertain, or a step could create irreversible or real-world impact. Payment, destructive, third-party, privilege-escalation, authentication-bypass, amplification, and denial-of-service actions are prohibited.

Sensitive-looking field names, administrative operation names, object identifier arguments, mutation names, schema visibility, and introspection availability can all be false positives. Runtime authorization must be demonstrated with controlled differential evidence before an authorization failure can be verified.
