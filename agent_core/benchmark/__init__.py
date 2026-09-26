"""Formal blind benchmark framework for autonomous security research."""

from agent_core.benchmark.integrity import (
    BenchmarkIntegrityVerifier,
    artifact_fingerprint,
    canonical_artifact_bytes,
)
from agent_core.benchmark.isolation import (
    BenchmarkBlindnessError,
    BenchmarkBlindnessGuard,
    BenchmarkContaminationDetector,
    BenchmarkContaminationError,
    BenchmarkGroundTruthStore,
    BenchmarkIsolationError,
    BenchmarkResetController,
    BenchmarkSecretStore,
    BlindnessCheckResult,
    ContaminationCheckResult,
    ContaminationMatch,
    GroundTruthAccessError,
)
from agent_core.benchmark.manifest import (
    BenchmarkManifestError,
    build_research_input,
    load_benchmark_manifest,
    manifest_fingerprint,
)
from agent_core.benchmark.metrics import (
    BenchmarkMetricsCalculator,
    calculate_benchmark_metrics,
    safe_ratio,
)
from agent_core.benchmark.fixtures import (
    SyntheticBenchmarkFixture,
    synthetic_benchmark_fixtures,
)
from agent_core.benchmark.reporting import BenchmarkReporter
from agent_core.benchmark.runner import (
    AutonomousResearchBenchmarkRunner,
    BenchmarkExecutionBindings,
    BenchmarkPreflightError,
    BenchmarkRunNotFound,
    BenchmarkRunnerError,
    BenchmarkRunStore,
    BenchmarkSuiteRunner,
)
from agent_core.benchmark.scoring import (
    BenchmarkComparator,
    BenchmarkRegressionGate,
    BenchmarkScorer,
    ChainMatcher,
    FindingMatcher,
    compare_benchmark_scores,
    observed_finding_from_record,
)
from agent_core.benchmark.types import *  # noqa: F403
from agent_core.benchmark.types import __all__ as _types_all

__all__ = [
    *_types_all,
    "AutonomousResearchBenchmarkRunner",
    "BenchmarkBlindnessError",
    "BenchmarkBlindnessGuard",
    "BenchmarkContaminationDetector",
    "BenchmarkContaminationError",
    "BenchmarkComparator",
    "BenchmarkExecutionBindings",
    "BenchmarkGroundTruthStore",
    "BenchmarkIntegrityVerifier",
    "BenchmarkIsolationError",
    "BenchmarkManifestError",
    "BenchmarkMetricsCalculator",
    "BenchmarkPreflightError",
    "BenchmarkRegressionGate",
    "BenchmarkReporter",
    "BenchmarkResetController",
    "BenchmarkRunNotFound",
    "BenchmarkRunnerError",
    "BenchmarkRunStore",
    "BenchmarkSuiteRunner",
    "BenchmarkScorer",
    "BenchmarkSecretStore",
    "BlindnessCheckResult",
    "ChainMatcher",
    "ContaminationCheckResult",
    "ContaminationMatch",
    "FindingMatcher",
    "GroundTruthAccessError",
    "SyntheticBenchmarkFixture",
    "artifact_fingerprint",
    "build_research_input",
    "calculate_benchmark_metrics",
    "canonical_artifact_bytes",
    "compare_benchmark_scores",
    "load_benchmark_manifest",
    "manifest_fingerprint",
    "observed_finding_from_record",
    "safe_ratio",
    "synthetic_benchmark_fixtures",
]
