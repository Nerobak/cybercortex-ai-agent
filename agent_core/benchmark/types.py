"""Strict contracts for blind autonomous-security research benchmarks.

The public input and private ground-truth types deliberately have no shared
base object or conversion method.  A runner must construct the former from a
manifest and may only resolve the latter after research has terminated.
"""

from __future__ import annotations

from enum import Enum
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    AliasChoices,
    model_validator,
)

from agent_core.result_normalizer import sanitize_document_text
from agent_core.models import ModelUsageDelta
from agent_core.research.types import TargetClass


def _public(value: str) -> str:
    if sanitize_document_text(value) != value:
        raise ValueError("benchmark text must already be public-safe")
    return value


Identifier = Annotated[
    StrictStr,
    Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$"),
]
Digest = Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
def _timestamp(value: str) -> str:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("benchmark timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("benchmark timestamp must include a UTC offset")
    return value


Timestamp = Annotated[
    StrictStr, Field(min_length=20, max_length=40), AfterValidator(_timestamp)
]
PublicText = Annotated[
    StrictStr, Field(min_length=1, max_length=8_000), AfterValidator(_public)
]


class BenchmarkContract(BaseModel):
    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
    )


class AllowedStateChangeClass(str, Enum):
    none = "none"
    read_only = "read_only"
    controlled_reversible = "controlled_reversible"
    controlled_fixture = "controlled_fixture"


class ResetStrategy(str, Enum):
    external_operator_reset = "external_operator_reset"
    fixture_reset_callback = "fixture_reset_callback"
    container_fixture_reset = "container_fixture_reset"
    database_fixture_reset = "database_fixture_reset"
    stateless_target = "stateless_target"


class BenchmarkRunStatus(str, Enum):
    created = "created"
    validated = "validated"
    resetting = "resetting"
    ready = "ready"
    running = "running"
    completed = "completed"
    failed = "failed"
    invalid = "invalid"
    contaminated = "contaminated"
    scoring = "scoring"
    scored = "scored"

    @property
    def research_terminated(self) -> bool:
        return self in {
            BenchmarkRunStatus.completed,
            BenchmarkRunStatus.failed,
            BenchmarkRunStatus.invalid,
            BenchmarkRunStatus.contaminated,
            BenchmarkRunStatus.scoring,
            BenchmarkRunStatus.scored,
        }


class IntegrityStatus(str, Enum):
    pending = "pending"
    verified = "verified"
    failed = "failed"


class FindingMatchClassification(str, Enum):
    exact_match = "exact_match"
    semantic_typed_match = "semantic_typed_match"
    partial_match = "partial_match"
    no_match = "no_match"
    ambiguous = "ambiguous"


class UnexpectedFindingStatus(str, Enum):
    unreviewed = "unreviewed"
    accepted_valid = "accepted_valid"
    rejected_false_positive = "rejected_false_positive"
    duplicate = "duplicate"
    out_of_scope = "out_of_scope"


class BenchmarkEventType(str, Enum):
    benchmark_created = "BENCHMARK_CREATED"
    blindness_validated = "BLINDNESS_VALIDATED"
    contamination_checked = "CONTAMINATION_CHECKED"
    reset_confirmed = "RESET_CONFIRMED"
    run_started = "RUN_STARTED"
    run_completed = "RUN_COMPLETED"
    run_failed = "RUN_FAILED"
    scoring_started = "SCORING_STARTED"
    scoring_completed = "SCORING_COMPLETED"
    integrity_verified = "INTEGRITY_VERIFIED"


class ScoreProfile(str, Enum):
    discovery_focused = "discovery_focused"
    confirmation_focused = "confirmation_focused"
    efficiency_focused = "efficiency_focused"
    balanced = "balanced"


class BenchmarkMetadataEntry(BenchmarkContract):
    key: Identifier
    value: PublicText


class BenchmarkModelRouting(BenchmarkContract):
    """Public, credential-free model route requested by the operator."""

    policy_reference: Identifier
    provider: Identifier
    requested_model: Identifier
    configuration_fingerprint: Digest


class BenchmarkResetPlan(BenchmarkContract):
    strategy: ResetStrategy
    reset_reference: Identifier
    operator_confirmation_required: StrictBool = False
    fixture_reference: Identifier | None = None
    verification_reference: Identifier | None = None

    @model_validator(mode="after")
    def validate_plan(self) -> "BenchmarkResetPlan":
        callback_strategies = {
            ResetStrategy.fixture_reset_callback,
            ResetStrategy.container_fixture_reset,
            ResetStrategy.database_fixture_reset,
        }
        if self.strategy in callback_strategies and self.fixture_reference is None:
            raise ValueError("fixture reset strategies require a fixture reference")
        if self.strategy is ResetStrategy.external_operator_reset and not (
            self.operator_confirmation_required
        ):
            raise ValueError("external reset requires operator confirmation")
        return self


class BenchmarkManifest(BenchmarkContract):
    """Immutable operator-visible configuration; never contains benchmark answers."""

    benchmark_id: Identifier
    benchmark_version: Identifier
    title: PublicText
    description: PublicText
    target_class: TargetClass
    authorized_target_reference: PublicText
    scope_reference: Identifier
    controlled_account_metadata_references: tuple[Identifier, ...] = Field(
        default=(), max_length=100
    )
    policy_reference: Identifier
    request_budget: StrictInt = Field(ge=1, le=10_000_000)
    model_budget: StrictInt = Field(ge=0, le=1_000_000)
    experiment_budget: StrictInt = Field(ge=0, le=100_000)
    reproduction_budget: StrictInt = Field(ge=0, le=100_000)
    chain_budget: StrictInt = Field(ge=0, le=100_000)
    wall_time_budget: StrictFloat = Field(ge=0.001, le=31_536_000.0)
    allowed_state_change_class: AllowedStateChangeClass
    reset_strategy: ResetStrategy
    ground_truth_reference: Identifier
    scoring_policy_reference: Identifier
    benchmark_tags: tuple[Identifier, ...] = Field(default=(), max_length=100)
    created_at: Timestamp

    @model_validator(mode="after")
    def canonicalize(self) -> "BenchmarkManifest":
        for name in ("controlled_account_metadata_references", "benchmark_tags"):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must not contain duplicates")
            object.__setattr__(self, name, tuple(sorted(values)))
        return self


class BenchmarkBudgetSnapshot(BenchmarkContract):
    request_budget: StrictInt = Field(ge=1)
    model_budget: StrictInt = Field(ge=0)
    experiment_budget: StrictInt = Field(ge=0)
    reproduction_budget: StrictInt = Field(ge=0)
    chain_budget: StrictInt = Field(ge=0)
    wall_time_budget: StrictFloat = Field(ge=0.001)


class BenchmarkResearchInput(BenchmarkContract):
    """The only benchmark-derived object allowed into production research."""

    benchmark_run_id: Identifier
    authorized_target: PublicText
    target_class: TargetClass
    scope_reference: Identifier
    policy_reference: Identifier
    controlled_identity_metadata_references: tuple[Identifier, ...] = Field(
        default=(), max_length=100
    )
    opaque_credential_references: tuple[Identifier, ...] = Field(
        default=(), max_length=100
    )
    budgets: BenchmarkBudgetSnapshot
    model_routing_policy: BenchmarkModelRouting
    safe_benchmark_metadata: tuple[BenchmarkMetadataEntry, ...] = Field(
        default=(), max_length=100
    )
    persistence_location: PublicText
    persistent_learning: StrictBool = False

    @model_validator(mode="after")
    def canonicalize(self) -> "BenchmarkResearchInput":
        for name in (
            "controlled_identity_metadata_references",
            "opaque_credential_references",
        ):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must not contain duplicates")
            object.__setattr__(self, name, tuple(sorted(values)))
        keys = tuple(item.key for item in self.safe_benchmark_metadata)
        if len(keys) != len(set(keys)):
            raise ValueError("safe benchmark metadata keys must be unique")
        from agent_core.research.provenance import reject_secret_material

        reject_secret_material(
            self.model_dump(mode="json"), location="benchmark research input"
        )
        return self


class FindingEquivalenceRules(BenchmarkContract):
    category_aliases: tuple[Identifier, ...] = ()
    endpoint_aliases: tuple[PublicText, ...] = ()
    parameter_aliases: tuple[Identifier, ...] = ()
    security_property_aliases: tuple[PublicText, ...] = ()
    primitive_aliases: tuple[Identifier, ...] = ()
    endpoint_case_sensitive: StrictBool = False
    parameter_case_sensitive: StrictBool = False


class GroundTruthFinding(BenchmarkContract):
    ground_truth_id: Identifier
    category: Identifier
    affected_surface_class: Identifier
    affected_endpoint_reference: PublicText
    affected_parameter_reference: Identifier | None = None
    affected_object_reference: Identifier | None = None
    security_property: PublicText
    required_controlled_identity_relationship: Identifier | None = None
    required_controlled_object_relationship: Identifier | None = None
    expected_vulnerable_behavior_class: PublicText
    expected_secure_behavior_class: PublicText
    severity_reference: Identifier
    confirmation_requirements: tuple[Identifier, ...] = Field(default=(), max_length=50)
    equivalence_rules: FindingEquivalenceRules = Field(
        default_factory=FindingEquivalenceRules
    )
    notes_safe_for_post_run_scoring_only: PublicText | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "notes_safe_for_post_run_scoring_only", "notes"
        ),
    )


class GroundTruthChain(BenchmarkContract):
    chain_ground_truth_id: Identifier
    component_ground_truth_ids: tuple[Identifier, ...] = Field(
        min_length=2, max_length=20
    )
    ordered_relationship_classes: tuple[Identifier, ...] = Field(
        min_length=1, max_length=19
    )
    required_cross_surface_transitions: tuple[Identifier, ...] = Field(
        default=(), max_length=20
    )
    combined_security_property: PublicText
    expected_combined_impact: PublicText
    confirmation_requirements: tuple[Identifier, ...] = Field(default=(), max_length=50)

    @model_validator(mode="after")
    def validate_chain(self) -> "GroundTruthChain":
        if len(self.component_ground_truth_ids) != len(
            set(self.component_ground_truth_ids)
        ):
            raise ValueError("ground-truth chain components must be unique")
        if len(self.ordered_relationship_classes) != len(
            self.component_ground_truth_ids
        ) - 1:
            raise ValueError("a chain requires one relationship between each component")
        return self


class BenchmarkGroundTruth(BenchmarkContract):
    benchmark_id: Identifier
    benchmark_version: Identifier
    findings: tuple[GroundTruthFinding, ...] = Field(default=(), max_length=10_000)
    chains: tuple[GroundTruthChain, ...] = Field(default=(), max_length=2_000)
    hidden_sentinels: tuple[PublicText, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def validate_truth(self) -> "BenchmarkGroundTruth":
        ids = tuple(item.ground_truth_id for item in self.findings)
        if len(ids) != len(set(ids)):
            raise ValueError("ground-truth finding IDs must be unique")
        chain_ids = tuple(item.chain_ground_truth_id for item in self.chains)
        if len(chain_ids) != len(set(chain_ids)):
            raise ValueError("ground-truth chain IDs must be unique")
        unknown = {
            component
            for chain in self.chains
            for component in chain.component_ground_truth_ids
            if component not in ids
        }
        if unknown:
            raise ValueError("ground-truth chains contain unknown findings")
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=lambda x: x.ground_truth_id)))
        object.__setattr__(self, "chains", tuple(sorted(self.chains, key=lambda x: x.chain_ground_truth_id)))
        return self


class BenchmarkObservedFinding(BenchmarkContract):
    finding_id: Identifier
    status: Identifier
    category: Identifier
    target_reference: PublicText | None = None
    surface_class: Identifier | None = None
    endpoint_reference: PublicText | None = None
    parameter_reference: Identifier | None = None
    object_reference: Identifier | None = None
    security_property: PublicText | None = None
    identity_relationship: Identifier | None = None
    object_relationship: Identifier | None = None
    primitive: Identifier | None = None
    evidence_class: Identifier | None = None


class FindingMatchDimensions(BenchmarkContract):
    category: StrictBool = False
    target_surface: StrictBool = False
    endpoint: StrictBool = False
    parameter: StrictBool = False
    security_property: StrictBool = False
    identity_relationship: StrictBool = False
    object_relationship: StrictBool = False
    object_reference: StrictBool = False
    primitive_evidence: StrictBool = False


class FindingMatch(BenchmarkContract):
    finding_id: Identifier
    ground_truth_id: Identifier | None = None
    classification: FindingMatchClassification
    dimensions: FindingMatchDimensions = Field(default_factory=FindingMatchDimensions)
    competing_ground_truth_ids: tuple[Identifier, ...] = ()


class BenchmarkObservedChain(BenchmarkContract):
    chain_id: Identifier
    status: Identifier
    component_finding_ids: tuple[Identifier, ...] = Field(min_length=2, max_length=20)
    ordered_relationship_classes: tuple[Identifier, ...] = Field(default=(), max_length=19)
    surface_classes: tuple[Identifier, ...] = Field(default=(), max_length=20)
    combined_security_property: PublicText | None = None
    combined_impact: PublicText | None = None


class ChainMatch(BenchmarkContract):
    chain_id: Identifier
    chain_ground_truth_id: Identifier | None = None
    classification: FindingMatchClassification
    component_matches: tuple[Identifier, ...] = ()
    relationships_match: StrictBool = False
    cross_surface_match: StrictBool = False
    security_property_match: StrictBool = False
    impact_match: StrictBool = False
    competing_chain_ground_truth_ids: tuple[Identifier, ...] = ()


class UnexpectedFindingRecord(BenchmarkContract):
    finding_id: Identifier
    status: UnexpectedFindingStatus = UnexpectedFindingStatus.unreviewed
    adjudication_reference: Identifier | None = None
    rationale: PublicText | None = None

    @model_validator(mode="after")
    def validate_adjudication(self) -> "UnexpectedFindingRecord":
        if self.status is UnexpectedFindingStatus.unreviewed and (
            self.adjudication_reference is not None
        ):
            raise ValueError("an unreviewed finding cannot have adjudication")
        if self.status is not UnexpectedFindingStatus.unreviewed and (
            self.adjudication_reference is None
        ):
            raise ValueError("reviewed unexpected findings require adjudication")
        return self


class BenchmarkScoringPolicy(BenchmarkContract):
    policy_id: Identifier
    minimum_confirmed_recall: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    maximum_false_confirmations: StrictInt = Field(default=0, ge=0)
    maximum_false_positive_rate: StrictFloat = Field(default=1.0, ge=0.0, le=1.0)
    maximum_target_requests: StrictInt | None = Field(default=None, ge=0)
    maximum_model_calls: StrictInt | None = Field(default=None, ge=0)
    maximum_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    maximum_wall_time_seconds: StrictFloat | None = Field(default=None, ge=0.0)
    zero_scope_violations: StrictBool = True
    zero_policy_violations: StrictBool = True
    zero_unauthorized_execution: StrictBool = True
    zero_secret_leakage: StrictBool = True
    required_chain_recall: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    score_profile: ScoreProfile = ScoreProfile.balanced
    unexpected_findings_are_false_positives: StrictBool = False
    component_weights: "ScoreComponentWeights" = Field(
        default_factory=lambda: ScoreComponentWeights()
    )

    @classmethod
    def for_profile(
        cls, policy_id: str, profile: ScoreProfile, **overrides: object
    ) -> "BenchmarkScoringPolicy":
        presets = {
            ScoreProfile.discovery_focused: (0.50, 0.20, 0.15, 0.05, 0.05, 0.05),
            ScoreProfile.confirmation_focused: (0.20, 0.45, 0.20, 0.05, 0.05, 0.05),
            ScoreProfile.efficiency_focused: (0.20, 0.15, 0.10, 0.25, 0.20, 0.10),
            ScoreProfile.balanced: (0.30, 0.25, 0.15, 0.10, 0.10, 0.10),
        }
        values = presets[profile]
        weights = ScoreComponentWeights(
            discovery_effectiveness=values[0],
            confirmation_quality=values[1],
            false_positive_penalty=values[2],
            request_efficiency=values[3],
            model_efficiency=values[4],
            safety=values[5],
        )
        return cls(
            policy_id=policy_id,
            score_profile=profile,
            component_weights=weights,
            **overrides,
        )


class ScoreComponentWeights(BenchmarkContract):
    discovery_effectiveness: StrictFloat = Field(default=0.30, ge=0.0, le=1.0)
    confirmation_quality: StrictFloat = Field(default=0.25, ge=0.0, le=1.0)
    false_positive_penalty: StrictFloat = Field(default=0.15, ge=0.0, le=1.0)
    request_efficiency: StrictFloat = Field(default=0.10, ge=0.0, le=1.0)
    model_efficiency: StrictFloat = Field(default=0.10, ge=0.0, le=1.0)
    safety: StrictFloat = Field(default=0.10, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def weights_sum_to_one(self) -> "ScoreComponentWeights":
        if abs(sum(self.model_dump().values()) - 1.0) > 1e-9:
            raise ValueError("benchmark score component weights must sum to 1")
        return self


class DiscoveryMetrics(BenchmarkContract):
    ground_truth_findings_total: StrictInt = Field(ge=0)
    candidate_findings: StrictInt = Field(ge=0)
    confirmed_findings: StrictInt = Field(ge=0)
    true_positive_candidates: StrictInt = Field(ge=0)
    true_positive_confirmed: StrictInt = Field(ge=0)
    missed_findings: StrictInt = Field(ge=0)
    false_positive_candidates: StrictInt = Field(ge=0)
    false_positive_confirmed: StrictInt = Field(ge=0)
    unexpected_findings: StrictInt = Field(ge=0)
    candidate_recall: StrictFloat = Field(ge=0.0, le=1.0)
    confirmed_recall: StrictFloat = Field(ge=0.0, le=1.0)
    candidate_precision: StrictFloat = Field(ge=0.0, le=1.0)
    confirmed_precision: StrictFloat = Field(ge=0.0, le=1.0)


class ConfirmationMetrics(BenchmarkContract):
    candidates_reproduced: StrictInt = Field(ge=0)
    candidates_confirmed: StrictInt = Field(ge=0)
    candidates_rejected: StrictInt = Field(ge=0)
    candidates_manual_review: StrictInt = Field(ge=0)
    confirmation_rate: StrictFloat = Field(ge=0.0, le=1.0)
    false_confirmation_count: StrictInt = Field(ge=0)
    reproduction_success_rate: StrictFloat = Field(ge=0.0, le=1.0)
    reproduction_request_cost: StrictInt = Field(ge=0)


class HypothesisMetrics(BenchmarkContract):
    hypotheses_generated: StrictInt = Field(ge=0)
    hypotheses_supported: StrictInt = Field(ge=0)
    hypotheses_refuted: StrictInt = Field(ge=0)
    hypotheses_inconclusive: StrictInt = Field(ge=0)
    useful_hypotheses: StrictInt = Field(ge=0)
    wasted_hypotheses: StrictInt = Field(ge=0)
    correct_refutations: StrictInt = Field(ge=0)
    hypothesis_to_candidate_conversion: StrictFloat = Field(ge=0.0, le=1.0)


class ExperimentMetrics(BenchmarkContract):
    experiments_attempted: StrictInt = Field(ge=0)
    experiments_secure_signal: StrictInt = Field(ge=0)
    experiments_vulnerable_signal: StrictInt = Field(ge=0)
    experiments_inconclusive: StrictInt = Field(ge=0)
    experiments_blocked: StrictInt = Field(ge=0)
    experiments_failed: StrictInt = Field(ge=0)
    requests_per_experiment: StrictFloat = Field(ge=0.0)
    experiments_per_confirmed_finding: StrictFloat = Field(ge=0.0)
    inconclusive_rate: StrictFloat = Field(ge=0.0, le=1.0)
    duplicate_experiment_blocks: StrictInt = Field(ge=0)
    policy_blocks: StrictInt = Field(ge=0)


class PivotMetrics(BenchmarkContract):
    pivots_attempted: StrictInt = Field(ge=0)
    material_pivots: StrictInt = Field(ge=0)
    successful_pivots: StrictInt = Field(ge=0)
    duplicate_pivots_blocked: StrictInt = Field(ge=0)
    pivots_to_new_finding: StrictInt = Field(ge=0)
    pivots_to_confirmation: StrictInt = Field(ge=0)


class ChainMetrics(BenchmarkContract):
    chain_candidates: StrictInt = Field(ge=0)
    chain_hypotheses: StrictInt = Field(ge=0)
    chains_tested: StrictInt = Field(ge=0)
    chains_supported: StrictInt = Field(ge=0)
    chains_refuted: StrictInt = Field(ge=0)
    chains_inconclusive: StrictInt = Field(ge=0)
    candidate_chain_findings: StrictInt = Field(ge=0)
    confirmed_chain_findings: StrictInt = Field(ge=0)
    true_positive_chains: StrictInt = Field(ge=0)
    missed_chains: StrictInt = Field(ge=0)
    unexpected_chains: StrictInt = Field(ge=0)
    chain_recall: StrictFloat = Field(ge=0.0, le=1.0)
    chain_precision: StrictFloat = Field(ge=0.0, le=1.0)
    chain_requests: StrictInt = Field(ge=0)
    chain_model_calls: StrictInt = Field(ge=0)
    chain_depth_distribution: tuple[StrictInt, ...] = ()


class ResourceMetrics(BenchmarkContract):
    total_target_requests: StrictInt = Field(ge=0)
    discovery_requests: StrictInt = Field(ge=0)
    verification_requests: StrictInt = Field(ge=0)
    reproduction_requests: StrictInt = Field(ge=0)
    chain_requests: StrictInt = Field(ge=0)
    cleanup_requests: StrictInt = Field(ge=0)
    model_calls: StrictInt = Field(ge=0)
    successful_model_calls: StrictInt = Field(ge=0)
    failed_model_calls: StrictInt = Field(ge=0)
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)
    total_tokens: StrictInt = Field(ge=0)
    estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    wall_time_seconds: StrictFloat = Field(ge=0.0)
    requests_per_candidate: StrictFloat = Field(ge=0.0)
    requests_per_confirmed_finding: StrictFloat = Field(ge=0.0)
    model_calls_per_confirmed_finding: StrictFloat = Field(ge=0.0)
    tokens_per_confirmed_finding: StrictFloat = Field(ge=0.0)
    cost_per_confirmed_finding: StrictFloat | None = Field(default=None, ge=0.0)


class TimeMetrics(BenchmarkContract):
    time_to_first_hypothesis: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_experiment: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_candidate: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_confirmed_finding: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_confirmed_chain: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_completion: StrictFloat = Field(ge=0.0)


class SafetyMetrics(BenchmarkContract):
    scope_violations: StrictInt = Field(default=0, ge=0)
    policy_violations: StrictInt = Field(default=0, ge=0)
    budget_violations: StrictInt = Field(default=0, ge=0)
    unauthorized_execution_attempts: StrictInt = Field(default=0, ge=0)
    secret_boundary_rejections: StrictInt = Field(default=0, ge=0)
    cleanup_failures: StrictInt = Field(default=0, ge=0)
    alternate_transport_attempts: StrictInt = Field(default=0, ge=0)


class BenchmarkMetrics(BenchmarkContract):
    discovery: DiscoveryMetrics
    confirmation: ConfirmationMetrics
    hypotheses: HypothesisMetrics
    experiments: ExperimentMetrics
    pivots: PivotMetrics
    chains: ChainMetrics
    resources: ResourceMetrics
    timing: TimeMetrics
    safety: SafetyMetrics


class ScoringRequirementResult(BenchmarkContract):
    requirement: Identifier
    passed: StrictBool
    observed: StrictFloat
    threshold: StrictFloat


class BenchmarkScore(BenchmarkContract):
    benchmark_run_id: Identifier
    benchmark_id: Identifier | None = None
    benchmark_version: Identifier | None = None
    policy_id: Identifier
    metrics: BenchmarkMetrics
    finding_matches: tuple[FindingMatch, ...] = ()
    chain_matches: tuple[ChainMatch, ...] = ()
    unexpected_findings: tuple[UnexpectedFindingRecord, ...] = ()
    requirements: tuple[ScoringRequirementResult, ...] = ()
    passed: StrictBool
    composite_score: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    score_profile: ScoreProfile


class BenchmarkRun(BenchmarkContract):
    run_id: Identifier
    benchmark_id: Identifier
    benchmark_version: Identifier
    research_id: Identifier
    status: BenchmarkRunStatus
    start_timestamp: Timestamp | None = None
    end_timestamp: Timestamp | None = None
    configuration_fingerprint: Digest
    code_revision: Identifier
    model_routing_fingerprint: Digest
    budget_snapshot: BenchmarkBudgetSnapshot
    initial_state_fingerprint: Digest | None = None
    final_state_fingerprint: Digest | None = None
    result_reference: Identifier | None = None
    scoring_reference: Identifier | None = None
    integrity_status: IntegrityStatus = IntegrityStatus.pending
    benchmark_manifest_fingerprint: Digest | None = None
    ground_truth_fingerprint: Digest | None = None
    scoring_policy_fingerprint: Digest | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "BenchmarkRun":
        started = {
            BenchmarkRunStatus.running,
            BenchmarkRunStatus.completed,
            BenchmarkRunStatus.failed,
            BenchmarkRunStatus.scoring,
            BenchmarkRunStatus.scored,
        }
        finished = {
            BenchmarkRunStatus.completed,
            BenchmarkRunStatus.failed,
            BenchmarkRunStatus.invalid,
            BenchmarkRunStatus.contaminated,
            BenchmarkRunStatus.scoring,
            BenchmarkRunStatus.scored,
        }
        if self.status in started and self.start_timestamp is None:
            raise ValueError("started benchmark status requires a start timestamp")
        if self.status in finished and self.end_timestamp is None:
            raise ValueError("terminated benchmark status requires an end timestamp")
        if self.status in {
            BenchmarkRunStatus.completed,
            BenchmarkRunStatus.scoring,
            BenchmarkRunStatus.scored,
        } and (
            self.final_state_fingerprint is None or self.result_reference is None
        ):
            raise ValueError("completed benchmark status requires a final result")
        if self.status is BenchmarkRunStatus.scored and self.scoring_reference is None:
            raise ValueError("scored benchmark status requires a scoring reference")
        if self.start_timestamp is not None and self.end_timestamp is not None:
            start = datetime.fromisoformat(
                self.start_timestamp.replace("Z", "+00:00")
            )
            end = datetime.fromisoformat(self.end_timestamp.replace("Z", "+00:00"))
            if end < start:
                raise ValueError("benchmark end timestamp precedes its start")
        if (
            self.integrity_status is IntegrityStatus.verified
            and self.status is not BenchmarkRunStatus.scored
        ):
            raise ValueError("only a scored run can have verified integrity")
        return self


class BenchmarkEvent(BenchmarkContract):
    event_id: Identifier
    run_id: Identifier
    sequence: StrictInt = Field(ge=0)
    event_type: BenchmarkEventType
    occurred_at: Timestamp
    previous_event_hash: Digest | None = None
    research_event_references: tuple[Identifier, ...] = Field(default=(), max_length=100)
    payload_fingerprint: Digest | None = None
    event_hash: Digest


class ReproducibilityMetadata(BenchmarkContract):
    git_commit_sha: Identifier
    dirty_working_tree: StrictBool
    python_version: PublicText
    platform: PublicText
    cybercortex_version: Identifier | None = None
    model_provider: Identifier
    requested_model: Identifier
    actual_model_provenance: tuple[Identifier, ...] = ()
    model_configuration_fingerprint: Digest
    policy_fingerprint: Digest
    benchmark_manifest_fingerprint: Digest
    ground_truth_fingerprint: Digest | None = None
    scoring_policy_fingerprint: Digest


class BenchmarkRuntimeMetadata(BenchmarkContract):
    wall_time_seconds: StrictFloat = Field(ge=0.0)
    request_snapshot: dict[Identifier, StrictInt]
    model_usage: ModelUsageDelta
    model_provider: Identifier
    requested_model: Identifier
    actual_model_provenance: tuple[Identifier, ...] = ()
    policy_fingerprint: Digest
    safety: SafetyMetrics = Field(default_factory=SafetyMetrics)
    failure_class: Identifier | None = None
    python_version: PublicText
    platform: PublicText


class BenchmarkIntegrityReport(BenchmarkContract):
    run_id: Identifier
    valid: StrictBool
    manifest_fingerprint: Digest
    ground_truth_fingerprint: Digest
    scoring_policy_fingerprint: Digest
    run_configuration_fingerprint: Digest
    initial_state_fingerprint: Digest
    final_state_fingerprint: Digest
    score_report_fingerprint: Digest
    mismatched_artifacts: tuple[Identifier, ...] = ()


class BenchmarkReport(BenchmarkContract):
    schema_version: Literal[1] = 1
    benchmark_id: Identifier
    benchmark_version: Identifier
    run_id: Identifier
    research_id: Identifier
    generated_at: Timestamp
    reproducibility: ReproducibilityMetadata
    score: BenchmarkScore
    integrity: BenchmarkIntegrityReport
    ground_truth_details_included: StrictBool = False
    ground_truth: BenchmarkGroundTruth | None = None

    @model_validator(mode="after")
    def validate_ground_truth_reporting(self) -> "BenchmarkReport":
        if self.ground_truth_details_included != (self.ground_truth is not None):
            raise ValueError("ground-truth reporting flag must match report contents")
        if self.score.benchmark_id not in {None, self.benchmark_id} or (
            self.score.benchmark_version not in {None, self.benchmark_version}
        ):
            raise ValueError("score identity differs from benchmark report")
        return self


class BenchmarkMetricDelta(BenchmarkContract):
    confirmed_recall: StrictFloat
    confirmed_precision: StrictFloat
    target_requests: StrictInt
    model_calls: StrictInt
    total_tokens: StrictInt
    cost_usd: StrictFloat | None = None
    wall_time_seconds: StrictFloat
    confirmed_chains: StrictInt
    safety_events: StrictInt


class BenchmarkComparison(BenchmarkContract):
    benchmark_id: Identifier
    benchmark_version: Identifier
    baseline_run_id: Identifier
    candidate_run_id: Identifier
    delta: BenchmarkMetricDelta


class BenchmarkRegressionTolerances(BenchmarkContract):
    confirmed_recall_decrease: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    false_confirmation_increase: StrictInt = Field(default=0, ge=0)
    request_increase: StrictInt = Field(default=0, ge=0)
    model_call_increase: StrictInt = Field(default=0, ge=0)
    chain_recall_decrease: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)


class BenchmarkRegressionResult(BenchmarkContract):
    passed: StrictBool
    reasons: tuple[Identifier, ...] = ()


class BenchmarkSuite(BenchmarkContract):
    suite_id: Identifier
    manifests: tuple[BenchmarkManifest, ...] = Field(min_length=1, max_length=1_000)
    concurrency: Literal[1] = 1

    @model_validator(mode="after")
    def validate_manifests(self) -> "BenchmarkSuite":
        identities = tuple(
            (item.benchmark_id, item.benchmark_version) for item in self.manifests
        )
        if len(identities) != len(set(identities)):
            raise ValueError("benchmark suite manifests must be unique")
        object.__setattr__(
            self,
            "manifests",
            tuple(
                sorted(
                    self.manifests,
                    key=lambda item: (item.benchmark_id, item.benchmark_version),
                )
            ),
        )
        return self

    def select(self, tags: tuple[str, ...] = ()) -> tuple[BenchmarkManifest, ...]:
        selected = self.manifests
        if tags:
            wanted = set(tags)
            selected = tuple(m for m in selected if wanted.intersection(m.benchmark_tags))
        return tuple(sorted(selected, key=lambda item: (item.benchmark_id, item.benchmark_version)))


__all__ = [name for name in tuple(globals()) if name.startswith("Benchmark") or name in {
    "AllowedStateChangeClass", "ResetStrategy", "IntegrityStatus",
    "FindingMatchClassification", "UnexpectedFindingStatus", "ScoreProfile",
    "ScoreComponentWeights",
    "GroundTruthFinding", "GroundTruthChain", "FindingEquivalenceRules",
    "FindingMatch", "FindingMatchDimensions", "ChainMatch", "DiscoveryMetrics",
    "ConfirmationMetrics", "HypothesisMetrics", "ExperimentMetrics", "PivotMetrics",
    "ChainMetrics", "ResourceMetrics", "TimeMetrics", "SafetyMetrics",
    "ReproducibilityMetadata", "UnexpectedFindingRecord", "ScoringRequirementResult",
}]
