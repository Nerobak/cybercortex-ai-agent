"""Canonical tool catalogue and scan profiles.

The registry contains metadata only.  Callables are imported lazily so a
missing optional dependency cannot prevent CyberCortex from starting.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any, Callable

DESCRIPTIVE_FIELDS = (
    "purpose",
    "expected_input",
    "evidence_collected",
    "limitations",
    "common_false_positives",
    "manual_verification",
    "bug_bounty_relevance",
    "example_usage",
    "safety_notes",
)


def _tool(
    description: str,
    category: str,
    module: str,
    callable_name: str,
    *,
    input_type: str = "target_url",
    prerequisites: tuple[str, ...] = (),
    requires_input: bool = False,
    requires_credentials: bool = False,
    network: bool = True,
    network_adapter: str | None = None,
    profiles: tuple[str, ...] = ("baseline", "deep", "authenticated"),
    expected_input: str = "An authorized in-scope target URL.",
    evidence: tuple[str, ...] = ("structured, source-attributed observations",),
    limitations: tuple[str, ...] = ("Automated output does not prove exploitability.",),
    false_positives: tuple[str, ...] = ("context-free or ambiguous matches",),
    verification: tuple[str, ...] = ("Review the evidence in application context.",),
    relevance: str = "Helps prioritize evidence-driven manual bug bounty review.",
    example: str = "scan https://authorized.example --profile baseline",
    safety: tuple[str, ...] = ("Use only on explicitly authorized scope.",),
) -> dict[str, Any]:
    return {
        "description": description,
        "category": category,
        "risk": "safe",
        "requires_scope": network,
        "module": module,
        "callable": callable_name,
        "expected_input_type": input_type,
        "prerequisites": list(prerequisites),
        "requires_explicit_input": requires_input,
        "requires_credentials": requires_credentials,
        "sends_network_traffic": network,
        "network_adapter": (network_adapter if network else None)
        or ("fail_closed" if network else None),
        "profiles": list(profiles),
        "purpose": description,
        "expected_input": expected_input,
        "evidence_collected": list(evidence),
        "limitations": list(limitations),
        "common_false_positives": list(false_positives),
        "manual_verification": list(verification),
        "bug_bounty_relevance": relevance,
        "example_usage": example,
        "safety_notes": list(safety),
    }


TOOLS: dict[str, dict[str, Any]] = {
    "dns_lookup": _tool(
        "Resolve DNS records and IP addresses.",
        "recon",
        "tools.dns_lookup",
        "dns_lookup",
        input_type="hostname",
        network_adapter="shared_dns",
    ),
    "http_probe": _tool(
        "Retrieve HTTP status and server information.",
        "recon",
        "tools.http_probe",
        "http_probe",
        network_adapter="shared_http",
    ),
    "security_headers_checker": _tool(
        "Inspect HTTP security headers.",
        "analysis",
        "tools.security_headers_checker",
        "security_headers_checker",
        network_adapter="shared_http",
    ),
    "tech_fingerprint": _tool(
        "Identify observed web technologies.",
        "recon",
        "tools.tech_fingerprint",
        "tech_fingerprint",
        network_adapter="shared_http",
    ),
    "katana_crawl": _tool(
        "Discover authorized endpoints with Katana.",
        "discovery",
        "tools.katana_crawl",
        "katana_crawl",
    ),
    "api_target_analyzer": _tool(
        "Evaluate deterministic API-target signals in existing discovery evidence.",
        "analysis",
        "tools.api_target_analyzer",
        "analyze_api_target",
        input_type="http_technology_and_crawl_evidence",
        prerequisites=("http_probe", "tech_fingerprint", "katana_crawl"),
        network=False,
        expected_input="Already-obtained HTTP, technology, redirect, route, and crawl evidence.",
        evidence=(
            "API-likelihood level",
            "deterministic signals",
            "adaptive discovery decision",
        ),
        limitations=(
            "API likelihood does not prove that OpenAPI metadata exists or that a vulnerability is present.",
        ),
        false_positives=(
            "JSON error responses and API-like routes used by non-API applications",
        ),
        verification=(
            "Require structural validation before treating a response as OpenAPI.",
        ),
        relevance="Decides when a bounded metadata pivot is justified after sparse crawling.",
        example="explain api_target_analyzer",
        safety=("Offline only; evaluates existing sanitized evidence.",),
    ),
    "api_metadata_discovery": _tool(
        "Discover structurally valid OpenAPI metadata at a fixed bounded set of common paths.",
        "discovery",
        "tools.api_metadata_discovery",
        "api_metadata_discovery",
        prerequisites=("api_target_analyzer",),
        network_adapter="shared_http",
        expected_input="An authorized reachable target with medium/high API likelihood and insufficient crawl surface.",
        evidence=(
            "scope-checked metadata request log",
            "validated OpenAPI documents",
            "safe redirect decisions",
        ),
        limitations=(
            "Only eight common metadata locations are considered; undocumented or nonstandard locations may be missed.",
        ),
        false_positives=(
            "None are promoted: every OpenAPI document requires version and paths structure.",
        ),
        verification=(
            "Review the documented routes against runtime behavior; documentation may be stale.",
        ),
        relevance="Recovers documented API attack surface when an ordinary root crawl yields little evidence.",
        example="explain api_metadata_discovery; scan https://authorized.example --profile baseline",
        safety=(
            "GET only; no wordlists, recursion, mutation, fuzzing, or out-of-scope redirects; strict request, timeout, and response-size bounds.",
        ),
    ),
    "openapi_surface_analyzer": _tool(
        "Parse an already-obtained OpenAPI 2.x/3.x document into normalized attack-surface evidence.",
        "analysis",
        "tools.openapi_surface_analyzer",
        "openapi_surface_analyzer",
        input_type="validated_openapi_document",
        prerequisites=("api_metadata_discovery",),
        network=False,
        expected_input="A structurally validated, already-obtained JSON or YAML OpenAPI document.",
        evidence=(
            "routes and methods",
            "parameters and body fields",
            "security requirements",
            "object-reference candidates",
            "schema names",
        ),
        limitations=(
            "Documentation may be incomplete or stale; external references are not resolved.",
        ),
        false_positives=(
            "Identifier-like field names are attack-surface observations, not authorization findings.",
        ),
        verification=(
            "Confirm documented operations with authorized runtime observations before drawing security conclusions.",
        ),
        relevance="Feeds documented operations into endpoint, parameter, object, upload, and planning analysis.",
        example="explain openapi_surface_analyzer",
        safety=(
            "Offline only; bounded local references; recursive reference loops stop; example/default values and sensitive metadata are omitted.",
        ),
    ),
    "endpoint_analyzer": _tool(
        "Analyze discovered endpoints.",
        "analysis",
        "tools.endpoint_analyzer",
        "endpoint_analyzer",
        input_type="normalized_urls",
        prerequisites=("katana_crawl", "openapi_surface_analyzer"),
        network=False,
    ),
    "parameter_analyzer": _tool(
        "Analyze parameters as manual test candidates.",
        "analysis",
        "tools.parameter_analyzer",
        "parameter_analyzer",
        input_type="normalized_urls",
        prerequisites=("katana_crawl", "openapi_surface_analyzer"),
        network=False,
    ),
    "misconfiguration_detector": _tool(
        "Identify configuration observations.",
        "analysis",
        "tools.misconfiguration_detector",
        "misconfiguration_detector",
        input_type="normalized_urls",
        prerequisites=("katana_crawl",),
        network=False,
    ),
    "js_secret_scanner": _tool(
        "Inspect authorized JavaScript resources.",
        "analysis",
        "tools.js_secret_scanner",
        "js_secret_scanner",
        input_type="javascript_urls",
        prerequisites=("katana_crawl",),
        network_adapter="shared_http",
        expected_input="Authorized JavaScript URLs normalized from crawl evidence.",
        evidence=(
            "redacted samples",
            "match kind and confidence",
            "line or offset",
            "context hash",
        ),
        limitations=(
            "A match does not prove a value is valid or grants access.",
            "Public contact information is informational.",
        ),
        false_positives=(
            "apiKey variable names",
            "placeholder or test values",
            "public support email addresses",
        ),
        verification=(
            "Confirm the value is real and active without using it beyond authorization.",
            "Confirm disclosure creates security impact.",
        ),
        relevance="Highlights credential-like candidates while separating public contact information.",
        example="explain js_secret_scanner; scan https://authorized.example --profile deep",
    ),
    "api_object_discovery": _tool(
        "Discover API object references with a bounded crawler.",
        "discovery",
        "tools.api_object_discovery",
        "crawl_and_discover_ids",
        prerequisites=("katana_crawl",),
        network_adapter="shared_http",
        expected_input="Normalized in-scope URLs, with an optional bounded crawl in deep profiles.",
        evidence=(
            "bounded path-segment classification summary",
            "identifier samples",
            "authorization-test candidate count",
        ),
        limitations=(
            "Route names and identifiers alone do not prove IDOR or authorization bypass.",
        ),
        false_positives=(
            "static asset filenames",
            "locales",
            "resource slugs and navigation routes",
        ),
        verification=(
            "Use controlled accounts to compare object access only when explicit authorization and context are available.",
        ),
        relevance="Identifies evidence that may justify controlled object-level authorization review.",
    ),
    "nuclei_scan": _tool(
        "Run approved Nuclei templates.", "active", "tools.nuclei_scan", "nuclei_scan"
    ),
    "jwt_security_analyzer": _tool(
        "Perform offline JWT structural analysis.",
        "authenticated",
        "tools.jwt_security_analyzer",
        "analyze_jwt",
        input_type="jwt",
        requires_input=True,
        network=False,
        profiles=("authenticated",),
        expected_input="A researcher-supplied JWT, preferably from a local ignored file or hidden prompt.",
        evidence=(
            "offline token structure",
            "algorithm and claim metadata without token disclosure",
        ),
        limitations=(
            "Structural analysis does not prove server-side token acceptance.",
        ),
        false_positives=(
            "unusual but valid claims",
            "development tokens with no production impact",
        ),
        verification=(
            "Verify behavior only through an explicitly authorized controlled workflow.",
        ),
        relevance="Supports planning of authorized JWT verification without automatically replaying credentials.",
        example="jwt analyze",
        safety=(
            "Token input is hidden and must never be printed or included in evidence.",
        ),
    ),
    "jwt_discovery": _tool(
        "Discover JWT metadata in existing authorized evidence without retaining credentials.",
        "discovery",
        "tools.jwt_discovery",
        "jwt_discovery",
        input_type="sanitized_authorized_evidence",
        network=False,
        profiles=("baseline", "deep", "authenticated"),
        expected_input="Captured request metadata, normalized headers/cookies, JavaScript strings, or controlled evidence.",
        evidence=(
            "redacted token fingerprints",
            "source, structure, and decoded presence metadata",
        ),
        limitations=(
            "JWT-like structure is an observation and does not prove server acceptance.",
        ),
        false_positives=(
            "unrelated dotted strings that happen to decode as JSON objects",
        ),
        verification=(
            "Review source context without recovering or displaying the credential.",
        ),
        relevance="Maps JWT-related authentication metadata already present in authorized evidence.",
        example="explain jwt_discovery",
        safety=("Offline only; raw tokens and signatures are never returned.",),
    ),
    "jwt_decoder": _tool(
        "Decode a researcher-controlled JWT offline with claim-value redaction.",
        "analysis",
        "tools.jwt_decoder",
        "jwt_decoder",
        input_type="controlled_jwt",
        prerequisites=("jwt_discovery",),
        requires_input=True,
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="One explicitly supplied controlled JWT.",
        evidence=(
            "safe header metadata",
            "claim-name and time-claim summaries",
            "signature presence",
        ),
        limitations=("No trusted key is supplied, so signatures are not verified.",),
        false_positives=("unusual but intentional claim and header conventions",),
        verification=(
            "Confirm policy and runtime enforcement through separately authorized controlled testing.",
        ),
        relevance="Provides secret-safe offline evidence for JWT review.",
        example="jwt analyze --file controlled.jwt",
        safety=("Never sends, stores, or prints the raw token or signature.",),
    ),
    "jwt_claims_analyzer": _tool(
        "Analyze controlled JWT header, claim-name, and time metadata deterministically.",
        "analysis",
        "tools.jwt_claims_analyzer",
        "jwt_claims_analyzer",
        input_type="controlled_decoded_jwt",
        prerequisites=("jwt_decoder",),
        requires_input=True,
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="A controlled token or successful in-process decoded evidence.",
        evidence=(
            "header observations",
            "registered/custom claim presence",
            "time classifications",
        ),
        limitations=(
            "Decoded claims never prove that a server enforces or accepts them.",
        ),
        false_positives=(
            "missing optional claims",
            "clock skew",
            "intentionally long-lived test tokens",
        ),
        verification=(
            "Use documented policy and controlled accounts for manual validation.",
        ),
        relevance="Prioritizes safe JWT policy review without promoting observations.",
        example="jwt analyze --file controlled.jwt",
        safety=(
            "Offline only; personal and authorization claim values are not exposed.",
        ),
    ),
    "jwt_comparison_analyzer": _tool(
        "Compare two or more researcher-controlled JWTs without displaying values.",
        "analysis",
        "tools.jwt_comparison_analyzer",
        "jwt_comparison_analyzer",
        input_type="controlled_jwt_set",
        prerequisites=("jwt_claims_analyzer",),
        requires_input=True,
        requires_credentials=True,
        network=False,
        profiles=("authenticated",),
        expected_input="At least two explicitly supplied controlled JWTs.",
        evidence=(
            "claim-name, header, lifetime, role/scope, and boundary differences",
        ),
        limitations=("Differences do not prove authorization bypass.",),
        false_positives=(
            "expected differences between access, refresh, or account tokens",
        ),
        verification=(
            "Validate boundaries using controlled accounts and test-owned resources.",
        ),
        relevance="Supports account and privilege-boundary review safely.",
        example="jwt compare account-a.jwt account-b.jwt",
        safety=("Raw claim values, tokens, and signatures are never returned.",),
    ),
    "jwt_verification_planner": _tool(
        "Create non-executing manual JWT verification plans.",
        "planning",
        "tools.jwt_verification_planner",
        "jwt_verification_planner",
        input_type="jwt_observations",
        prerequisites=("jwt_claims_analyzer",),
        requires_input=True,
        requires_credentials=True,
        network=False,
        profiles=("authenticated",),
        expected_input="Sufficient decoded claim or controlled comparison evidence.",
        evidence=(
            "prerequisites, safe steps, expected behavior, stop conditions, and prohibited actions",
        ),
        limitations=("Planning does not execute checks or establish findings.",),
        false_positives=("policy hypotheses unsupported by runtime evidence",),
        verification=(
            "Execute manually only with explicit authorization and controlled accounts.",
        ),
        relevance="Turns observations into bounded, reversible verification guidance.",
        example="jwt plan controlled.jwt",
        safety=("Automatic execution is always false.",),
    ),
    "jwt_replay_checker": _tool(
        "Perform one explicitly enabled, bounded replay of a controlled JWT request.",
        "authenticated",
        "tools.jwt_replay_checker",
        "jwt_replay_checker",
        input_type="controlled_request",
        prerequisites=("jwt_verification_planner",),
        requires_input=True,
        requires_credentials=True,
        profiles=("authenticated",),
        expected_input="An explicitly supplied in-scope request and researcher-owned token; JWT_REPLAY_ENABLED must be true.",
        evidence=(
            "status code, bounded response structure, redirect count, and safe metadata",
        ),
        limitations=("Token acceptance alone is an observation, not a vulnerability.",),
        false_positives=(
            "public endpoints",
            "cached responses",
            "expected token acceptance",
        ),
        verification=(
            "Compare against documented policy and controlled baseline evidence.",
        ),
        relevance="Supports minimal permitted runtime confirmation after manual planning.",
        example="JWT_REPLAY_ENABLED=true; jwt replay controlled-request.json",
        safety=(
            "Disabled by default; no mutation, brute force, key confusion, or unsafe redirects.",
        ),
    ),
    "authz_test_planner": _tool(
        "Turn parameter observations into conservative manual test ideas.",
        "planning",
        "tools.authz_test_planner",
        "authz_test_planner",
        input_type="parameter_findings",
        prerequisites=("parameter_analyzer",),
        network=False,
        profiles=("deep", "authenticated"),
    ),
    "graphql_endpoint_discovery": _tool(
        "Identify GraphQL endpoint observations from existing authorized evidence.",
        "discovery",
        "tools.graphql_endpoint_discovery",
        "graphql_endpoint_discovery",
        input_type="normalized_surface",
        prerequisites=("katana_crawl",),
        network=False,
        expected_input="Normalized crawler, endpoint, JavaScript, form, fetch/XHR, or captured-request evidence.",
        evidence=(
            "scope-validated endpoint candidates",
            "confidence and evidence types",
            "whether network testing occurred",
        ),
        limitations=(
            "Route names alone are observations and do not confirm GraphQL or a vulnerability.",
        ),
        false_positives=(
            "static assets mentioning GraphQL",
            "routes with generic query names",
        ),
        verification=(
            "Confirm endpoint behavior using existing response evidence or an explicitly permitted bounded check.",
        ),
        relevance="Maps GraphQL application behavior without sending attack payloads.",
        example="explain graphql_endpoint_discovery; scan https://authorized.example --profile baseline",
        safety=(
            "Offline by default; every candidate must pass configured domain and path-prefix scope.",
        ),
    ),
    "graphql_query_analyzer": _tool(
        "Inspect supplied GraphQL documents offline without executing them.",
        "analysis",
        "tools.graphql_query_analyzer",
        "analyze_graphql_query",
        input_type="graphql_query_evidence",
        prerequisites=("graphql_endpoint_discovery",),
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="A controlled GraphQL document supplied by the researcher or extracted from authorized evidence.",
        evidence=(
            "operation structure",
            "fields, arguments, variables, fragments, aliases, and depth",
            "sensitive-looking name observations",
        ),
        limitations=(
            "Names and structure do not establish exploitability or authorization failure.",
        ),
        false_positives=(
            "benign sensitive-looking field names",
            "client-only GraphQL documents",
        ),
        verification=(
            "Review observations in application context; execution is never automatic.",
        ),
        relevance="Supports safe GraphQL surface review and controlled test planning.",
        example="graphql analyze query.graphql",
        safety=(
            "Offline only; supplied queries are never executed.",
            "Mutations and amplification payloads are not sent.",
        ),
    ),
    "graphql_schema_analyzer": _tool(
        "Analyze already-obtained GraphQL schema data offline.",
        "analysis",
        "tools.graphql_schema_analyzer",
        "analyze_graphql_schema",
        input_type="graphql_schema_json",
        prerequisites=("graphql_query_analyzer",),
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="Already-obtained introspection JSON or schema-like structured input.",
        evidence=(
            "bounded type and operation counts",
            "authorization-sensitive planning categories",
            "deterministic truncation indicators",
        ),
        limitations=(
            "Schema names do not prove broken authorization.",
            "Representative output is bounded.",
        ),
        false_positives=(
            "administrative names protected correctly at runtime",
            "unused schema fields",
        ),
        verification=(
            "Use controlled accounts and test-owned objects for any manual authorization review.",
        ),
        relevance="Turns schema visibility into conservative manual-review priorities.",
        example="graphql schema schema.json",
        safety=("Offline only; raw schemas are not displayed by default.",),
    ),
    "graphql_introspection_checker": _tool(
        "Check GraphQL introspection with one standard bounded opt-in request.",
        "analysis",
        "tools.graphql_introspection_checker",
        "graphql_introspection_checker",
        input_type="confirmed_graphql_endpoint",
        prerequisites=("graphql_endpoint_discovery",),
        profiles=("deep", "authenticated"),
        expected_input="A confirmed or high-confidence in-scope GraphQL endpoint; GRAPHQL_INTROSPECTION_ENABLED must be true.",
        evidence=(
            "redacted response summary",
            "HTTP and introspection classification",
            "redirect and size-limit handling",
        ),
        limitations=(
            "Introspection availability is an observation, not a vulnerability.",
        ),
        false_positives=(
            "intentionally public schema discovery",
            "authenticated development tooling",
        ),
        verification=(
            "Review program policy and exposure context without promoting availability to a finding.",
        ),
        relevance="Records schema visibility safely when programs explicitly permit the check.",
        example="GRAPHQL_INTROSPECTION_ENABLED=true; scan https://authorized.example --profile deep",
        safety=(
            "Disabled by default.",
            "No mutations, aliases, batching, recursion, retries, or authentication bypass payloads.",
        ),
    ),
    "graphql_authz_planner": _tool(
        "Create manual GraphQL authorization plans for controlled accounts.",
        "planning",
        "tools.graphql_authz_planner",
        "graphql_authz_planner",
        input_type="controlled_graphql_evidence",
        prerequisites=("graphql_schema_analyzer",),
        network=False,
        profiles=("authenticated",),
        requires_input=True,
        requires_credentials=True,
        expected_input="Confirmed endpoint, analyzed operations, identifiers, and metadata for at least two controlled accounts.",
        evidence=(
            "safe manual steps",
            "required evidence and stop conditions",
            "prohibited actions",
        ),
        limitations=(
            "Planning does not establish or automatically test an authorization vulnerability.",
        ),
        false_positives=("ownership-sensitive names with correct runtime enforcement",),
        verification=(
            "Manually compare only researcher-controlled accounts and test-owned objects.",
        ),
        relevance="Supports evidence-driven object, field, and mutation authorization review.",
        example="explain graphql_authz_planner",
        safety=(
            "Planning only; automatic execution is always false.",
            "No third-party, payment, destructive, or irreversible actions.",
        ),
    ),
    "request_replay_engine": _tool(
        "Replay explicitly supplied controlled authorization contexts.",
        "authenticated",
        "tools.request_replay_engine",
        "replay_authorization_contexts",
        input_type="controlled_requests",
        requires_input=True,
        requires_credentials=True,
        profiles=("authenticated",),
    ),
    "authorization_differential_tester": _tool(
        "Classify controlled response differences.",
        "authenticated",
        "tools.authz_differential_tester",
        "analyze_authorization_difference",
        input_type="response_diff",
        prerequisites=("request_replay_engine",),
        requires_input=True,
        network=False,
        profiles=("authenticated",),
    ),
    "authenticated_injection_verifier": _tool(
        "Run one bounded, non-extracting boolean SQL injection differential check.",
        "authenticated",
        "tools.authenticated_injection_verifier",
        "verify_boolean_sql_injection",
        input_type="controlled_raw_http_request",
        requires_input=True,
        requires_credentials=True,
        profiles=("authenticated",),
        expected_input="One captured in-scope GET request and one explicit query parameter.",
        evidence=("response status, length, hashes, and similarity scores",),
        limitations=(
            "Dynamic responses can produce false positives or false negatives.",
            "A candidate requires manual confirmation and never triggers extraction.",
        ),
        false_positives=("personalized, randomized, cached, or unstable responses",),
        verification=("Repeat once and confirm behavior in controlled server logs.",),
        relevance="Provides bounded authenticated SQL injection evidence without enumeration.",
        example="python injection_cli.py --request verification_inputs/request.txt --parameter id --authorized",
        safety=(
            "Exactly three GET requests; no data extraction, writes, enumeration, or destructive payloads.",
        ),
    ),
    "request_mutation_engine": _tool(
        "Verify bounded authenticated XSS, SSTI, command, traversal, and SSRF canaries.",
        "authenticated",
        "tools.request_mutation_engine",
        "verify_request_mutations",
        input_type="controlled_raw_http_request",
        requires_input=True,
        requires_credentials=True,
        profiles=("authenticated",),
        expected_input="One captured in-scope GET request, one parameter, and explicit probe families.",
        evidence=("bounded response fingerprints and canary proof classifications",),
        limitations=(
            "Reflection alone does not prove script execution; SSRF requires callback confirmation.",
        ),
        false_positives=("application echo, caching, and unstable dynamic content",),
        verification=(
            "Confirm candidates with controlled browser, callback, or server-side evidence.",
        ),
        relevance="Adds non-destructive proof-oriented bug bounty verification.",
        example="python mutation_cli.py --request verification_inputs/request.txt --parameter name --families xss,ssti --authorized",
        safety=(
            "No persistence, extraction, state changes, system-file reads, or destructive commands.",
        ),
    ),
    "capture_verification_orchestrator": _tool(
        "Plan and execute bounded verification campaigns from authorized HTTP captures.",
        "orchestration",
        "agent_core.capture_verification_orchestrator",
        "run_campaign",
        input_type="controlled_capture_manifest",
        requires_input=True,
        requires_credentials=True,
        profiles=("authenticated",),
        expected_input="A local manifest referencing captured requests and explicit verification policy.",
        evidence=(
            "ranked parameter plan, bounded execution results, callback correlation, and deduplicated findings",
        ),
        limitations=(
            "Only supplied GET captures are currently executed; callback observations must be supplied.",
        ),
        false_positives=(
            "unstable responses and untrusted callback observation imports",
        ),
        verification=(
            "Review deduplicated proof and reproduce within the authorized scope.",
        ),
        relevance="Turns authenticated captures into evidence-driven bug bounty verification campaigns.",
        example="python campaign_cli.py --manifest verification_inputs/campaign.json --execute --authorized",
        safety=(
            "Explicit authorization, scope enforcement, request budgets, and secret-safe reports are mandatory.",
        ),
    ),
    "workflow_evidence_discovery": _tool(
        "Discover workflow candidates from sanitized authorized evidence.",
        "business_logic",
        "tools.workflow_evidence_discovery",
        "workflow_evidence_discovery",
        input_type="sanitized_workflow_evidence",
        requires_input=True,
        network=False,
        profiles=("baseline", "deep", "authenticated"),
        expected_input="Explicit local JSON containing sanitized request or workflow metadata.",
        evidence=(
            "ordered steps",
            "shared identifier categories",
            "state-field presence",
            "authentication-context presence",
        ),
        limitations=(
            "Route names alone remain low-confidence observations.",
            "No server-side enforcement is inferred.",
        ),
        false_positives=("unrelated requests captured in chronological order",),
        verification=(
            "Confirm candidate grouping against researcher-supplied controlled traces.",
        ),
        relevance="Maps workflow surface for bounded manual business-rule review.",
        example="workflow analyze controlled-workflow.json",
        safety=(
            "Offline only; bodies, credentials, tokens, cookies, personal data, and private values are not retained.",
        ),
    ),
    "workflow_model_builder": _tool(
        "Build a deterministic canonical workflow model.",
        "business_logic",
        "tools.workflow_model_builder",
        "workflow_model_builder",
        input_type="workflow_candidate",
        prerequisites=("workflow_evidence_discovery",),
        requires_input=True,
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="A medium- or high-confidence ordered workflow candidate.",
        evidence=(
            "canonical steps",
            "observed transitions",
            "actors",
            "resources",
            "unknowns",
        ),
        limitations=("Missing states and transitions remain unknown.",),
        false_positives=("captured order that is not required server order",),
        verification=(
            "Validate modeled order against application documentation and controlled evidence.",
        ),
        relevance="Creates deterministic input for transition and business-rule analysis.",
        example="workflow model controlled-workflow.json",
        safety=("Offline and bounded; never fabricates states or transitions.",),
    ),
    "workflow_transition_analyzer": _tool(
        "Analyze workflow transitions and boundaries offline.",
        "business_logic",
        "tools.workflow_transition_analyzer",
        "workflow_transition_analyzer",
        input_type="canonical_workflow_model",
        prerequisites=("workflow_model_builder",),
        requires_input=True,
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="A canonical workflow model.",
        evidence=(
            "ordering",
            "state-changing steps",
            "actor boundaries",
            "replay sensitivity",
            "idempotency metadata",
        ),
        limitations=(
            "Observations do not establish skipped-step or replay vulnerabilities.",
        ),
        false_positives=(
            "optional steps",
            "expected actor changes",
            "framework-generated fields",
        ),
        verification=(
            "Use minimal controlled-account tests only when explicitly authorized.",
        ),
        relevance="Prioritizes evidence-supported workflow hypotheses.",
        example="workflow analyze controlled-workflow.json",
        safety=("Offline only; incomplete evidence is labeled incomplete.",),
    ),
    "business_rule_analyzer": _tool(
        "Identify deterministic business-rule field and boundary observations.",
        "business_logic",
        "tools.business_rule_analyzer",
        "business_rule_analyzer",
        input_type="canonical_workflow_model",
        prerequisites=("workflow_transition_analyzer",),
        requires_input=True,
        network=False,
        profiles=("deep", "authenticated"),
        expected_input="A canonical workflow model containing parameter-name metadata.",
        evidence=("field categories", "rule categories", "manual-review hypotheses"),
        limitations=(
            "Parameter presence does not prove client trust or server weakness.",
        ),
        false_positives=("descriptive fields with no client control",),
        verification=(
            "Confirm enforcement with controlled accounts and test-owned resources.",
        ),
        relevance="Surfaces quantity, ownership, role, state, approval, and idempotency review areas.",
        example="workflow analyze controlled-workflow.json",
        safety=("Offline; values and bodies are excluded.",),
    ),
    "business_logic_test_planner": _tool(
        "Create non-executing safe business-logic verification plans.",
        "planning",
        "tools.business_logic_test_planner",
        "business_logic_test_planner",
        input_type="evidence_supported_workflow_model",
        prerequisites=("business_rule_analyzer",),
        requires_input=True,
        requires_credentials=True,
        network=False,
        profiles=("authenticated",),
        expected_input="Medium- or high-confidence controlled workflow evidence.",
        evidence=(
            "prerequisites",
            "safe steps",
            "stop conditions",
            "prohibited actions",
            "cleanup",
        ),
        limitations=("Plans do not execute checks or establish findings.",),
        false_positives=("hypotheses for behavior enforced correctly by the server",),
        verification=("Execute manually only under explicit authorization.",),
        relevance="Produces bounded verification guidance without automatic abuse.",
        example="workflow plan controlled-workflow.json",
        safety=(
            "Controlled accounts and test-owned resources are mandatory; financial, destructive, regulated, and security-setting workflows are blocked.",
        ),
    ),
    "workflow_replay_checker": _tool(
        "Optionally replay a minimal safe controlled workflow request.",
        "business_logic",
        "tools.workflow_replay_checker",
        "workflow_replay_checker",
        input_type="explicit_controlled_request_file",
        prerequisites=("business_logic_test_planner",),
        requires_input=True,
        requires_credentials=True,
        profiles=("authenticated",),
        expected_input="Explicit in-scope GET/HEAD requests with controlled-account and test-owned-resource confirmations.",
        evidence=("status class", "response size", "redirect count", "redacted path"),
        limitations=("Successful replay remains an observation.",),
        false_positives=("public endpoints", "cached or expected responses"),
        verification=("Compare against controlled baseline and documented policy.",),
        relevance="Allows a strictly bounded runtime observation after explicit opt-in.",
        example="BUSINESS_LOGIC_REPLAY_ENABLED=true; workflow replay controlled-request.json",
        safety=(
            "Disabled by default; no mutation, financial action, concurrency, parameter changes, raw secrets, or third-party access.",
        ),
    ),
    "upload_discovery": _tool(
        "Discover file-upload surface from existing authorized evidence.",
        "discovery",
        "tools.upload_discovery",
        "upload_discovery",
        input_type="normalized_upload_evidence",
        network=False,
        expected_input="Normalized forms, requests, JavaScript, endpoints, workflows, OpenAPI, or GraphQL evidence.",
        evidence=(
            "upload endpoint, multipart, file input, JavaScript, and Upload scalar observations",
        ),
        limitations=(
            "Upload-related evidence does not prove that an endpoint accepts files.",
        ),
        false_positives=("route names, static documentation, and unused client code",),
        verification=(
            "Confirm behavior manually with one benign researcher-owned file when explicitly authorized.",
        ),
        relevance="Maps upload functionality without sending files.",
        example="upload analyze controlled-upload-evidence.json",
        safety=("Offline only; file bodies and filenames are not retained.",),
    ),
    "upload_validation_analyzer": _tool(
        "Analyze observed file type, MIME, filename, and size validation evidence.",
        "analysis",
        "tools.upload_validation_analyzer",
        "upload_validation_analyzer",
        input_type="upload_evidence",
        prerequisites=("upload_discovery",),
        network=False,
        expected_input="Existing client, request, response, OpenAPI, or workflow metadata.",
        evidence=(
            "accepted/rejected type, extension, MIME, Content-Type, size, and validation hints",
        ),
        limitations=(
            "Absent evidence does not prove absent validation; server behavior is never inferred.",
        ),
        false_positives=(
            "client-only validation and documentation that differs from runtime behavior",
        ),
        verification=(
            "Compare documented and observed behavior using bounded benign files.",
        ),
        relevance="Identifies validation consistency questions requiring manual review.",
        example="upload analyze controlled-upload-evidence.json",
        safety=("Offline and observation-only.",),
    ),
    "upload_metadata_analyzer": _tool(
        "Observe upload filename, naming, path, disposition, and metadata handling.",
        "analysis",
        "tools.upload_metadata_analyzer",
        "upload_metadata_analyzer",
        input_type="upload_evidence",
        prerequisites=("upload_discovery",),
        network=False,
        expected_input="Sanitized request, response, code, workflow, or storage metadata.",
        evidence=(
            "filename/path handling, naming strategy, metadata stripping, disposition, and object-key hints",
        ),
        limitations=("Indicators do not prove the final storage name or path.",),
        false_positives=("framework defaults and unused implementation code",),
        verification=(
            "Review behavior with a researcher-owned benign file and redact filenames.",
        ),
        relevance="Supports filename normalization and metadata review.",
        example="upload analyze controlled-upload-evidence.json",
        safety=("Never returns supplied filenames or file content.",),
    ),
    "upload_storage_analyzer": _tool(
        "Classify observed upload storage-provider indicators.",
        "analysis",
        "tools.upload_storage_analyzer",
        "upload_storage_analyzer",
        input_type="upload_evidence",
        prerequisites=("upload_discovery",),
        network=False,
        expected_input="Sanitized URLs, headers, code, configuration names, or response metadata.",
        evidence=("S3, Azure Blob, GCS, CDN, or local-filesystem indicators",),
        limitations=(
            "Provider indicators do not prove storage exposure or public access.",
        ),
        false_positives=("unrelated SDKs, CDN assets, and documentation examples",),
        verification=(
            "Validate access only with test-owned objects and controlled accounts.",
        ),
        relevance="Maps likely storage architecture conservatively.",
        example="upload analyze controlled-upload-evidence.json",
        safety=("Observation-only and offline.",),
    ),
    "upload_security_planner": _tool(
        "Create safe non-executing manual upload verification plans.",
        "planning",
        "tools.upload_security_planner",
        "upload_security_planner",
        input_type="observed_upload_surface",
        prerequisites=(
            "upload_validation_analyzer",
            "upload_metadata_analyzer",
            "upload_storage_analyzer",
        ),
        network=False,
        requires_input=True,
        expected_input="Evidence demonstrating an observed upload surface.",
        evidence=(
            "prerequisites, safe steps, expected behavior, stop conditions, and prohibited actions",
        ),
        limitations=("Plans do not execute checks or establish vulnerabilities.",),
        false_positives=("hypotheses for controls enforced correctly by the server",),
        verification=(
            "Execute manually only with explicit authorization and researcher-owned benign files.",
        ),
        relevance="Turns upload observations into bounded manual checks.",
        example="upload plan controlled-upload-evidence.json",
        safety=(
            "Automatic execution is false; dangerous, third-party, archive, executable, and oversized files are prohibited.",
        ),
    ),
    "upload_replay_checker": _tool(
        "Optionally perform one bounded replay with a researcher-owned benign file.",
        "authenticated",
        "tools.upload_replay_checker",
        "upload_replay_checker",
        input_type="controlled_upload_request",
        prerequisites=("upload_security_planner",),
        profiles=("authenticated",),
        requires_input=True,
        requires_credentials=True,
        expected_input="An in-scope upload URL, explicit ownership confirmations, and a bounded local benign file.",
        evidence=("status code, response size, and response Content-Type only",),
        limitations=(
            "A successful upload is an observation and does not establish a vulnerability.",
        ),
        false_positives=("expected upload acceptance and public workflows",),
        verification=(
            "Compare only controlled baseline behavior and documented policy.",
        ),
        relevance="Supports minimal opt-in confirmation after manual planning.",
        example="UPLOAD_REPLAY_ENABLED=true; upload replay controlled-upload.json",
        safety=(
            "Disabled by default; blocks malware, exploits, shells, executables, archives, polyglots, oversized files, and third-party data.",
        ),
    ),
    "ai_report_writer": _tool(
        "Generate an evidence-based assessment report.",
        "reporting",
        "tools.ai_report_writer",
        "ai_report_writer",
        input_type="evidence_package",
        prerequisites=("normalized_evidence",),
        network=True,
        network_adapter="offline_fallback",
    ),
}

for _name, _metadata in TOOLS.items():
    _metadata["name"] = _name

SCAN_PROFILES = {
    "baseline": tuple(TOOLS),
    "deep": tuple(TOOLS),
    "authenticated": tuple(TOOLS),
    "intrusive": tuple(TOOLS),
}


def resolve_tool(name: str) -> Callable[..., Any] | None:
    info = TOOLS.get(name)
    if not info:
        return None
    try:
        value = getattr(import_module(info["module"]), info["callable"])
    except (ImportError, AttributeError):
        return None
    return value if callable(value) else None


def validate_registry() -> list[dict[str, Any]]:
    """Return diagnostic metadata for every canonical tool."""
    diagnostics = []
    for name, info in TOOLS.items():
        available = resolve_tool(name) is not None
        diagnostics.append(
            {
                "name": name,
                "status": "registered" if available else "unavailable",
                "callable_exists": available,
                "expected_input_type": info["expected_input_type"],
                "category": info["category"],
                "prerequisites": info["prerequisites"],
                "requires_credentials": info["requires_credentials"],
                "requires_explicit_input": info["requires_explicit_input"],
                "network": info["sends_network_traffic"],
                "profiles": info["profiles"],
                "metadata_complete": all(
                    info.get(field) for field in DESCRIPTIVE_FIELDS
                ),
            }
        )
    return diagnostics


def tools_for_profile(profile: str) -> list[str]:
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {profile}")
    eligibility_profile = "authenticated" if profile == "intrusive" else profile
    return [
        name
        for name in SCAN_PROFILES[profile]
        if eligibility_profile in TOOLS[name]["profiles"]
    ]
