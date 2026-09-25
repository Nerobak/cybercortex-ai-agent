from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

import research_cli
from agent_core.attack_surface import CanonicalAttackSurface, SurfaceEvidence
from agent_core.credential_vault import CredentialVault
from agent_core.models import ModelCallLedger, ModelErrorCode, ModelUsageDelta
from agent_core.research import (
    ExperimentCompiler,
    PublicSafeResearchPacketBuilder,
    ResearchExecutionGate,
    reject_secret_material,
)
from tests.test_phase4_research_compiler import (
    compiler_context as compiler_context_fixture,
)
from tests.test_phase4_research_compiler import object_proposal
from tests.test_phase4_research_compiler import (
    research_state as compiler_state_fixture,
)
from tests.test_phase4_research_runtime import build_runtime_fixture
from tools.safe_http import ScopedHTTPClient

SYNTHETIC_SECRET = "cli-secret-sentinel-7f4d2b"
TARGET = "https://research-cli.example"


def cli_args(tmp_path: Path, *extra: str):
    values = [
        "run",
        "--target",
        TARGET,
        "--target-class",
        "dedicated_lab",
        "--research-id",
        "cli-test-run",
        "--provider",
        "ollama",
        "--model",
        "local-test-model",
        "--request-budget",
        "30",
        "--model-call-budget",
        "8",
        "--experiment-budget",
        "6",
        "--pivot-budget",
        "2",
        "--wall-time",
        "900",
        "--read-only",
        "--database",
        str(tmp_path / "research.sqlite3"),
        *extra,
    ]
    return research_cli.build_parser().parse_args(values)


def controlled_environment() -> dict[str, str]:
    return {
        "CYBERCORTEX_ACCOUNT_A_ID": "alice",
        "CYBERCORTEX_ACCOUNT_A_TOKEN": SYNTHETIC_SECRET,
        "CYBERCORTEX_ACCOUNT_A_ROLE": "user",
        "CYBERCORTEX_ACCOUNT_B_ID": "bob",
        "CYBERCORTEX_ACCOUNT_B_TOKEN": SYNTHETIC_SECRET + "-b",
        "CYBERCORTEX_ACCOUNT_B_ROLE": "user",
    }


class FakeDiscoveryRunner:
    def __init__(self, budget):
        self.budget = budget
        self.calls = 0

    def run(self, target: str, **_kwargs):
        self.calls += 1
        self.budget.consume("discovery", host="research-cli.example")
        surface = CanonicalAttackSurface(
            target=target,
            routes=[
                {
                    "method": "GET",
                    "path": "/records/{record}",
                    "source": "synthetic-discovery",
                    "confidence": "high",
                    "evidence_refs": ["synthetic-record-capture"],
                    "content_types": ["application/json"],
                }
            ],
            parameters=[
                {
                    "method": "GET",
                    "path": "/records/{record}",
                    "name": "record",
                    "in": "path",
                    "schema_type": "string",
                    "required": True,
                    "source": "synthetic-discovery",
                    "confidence": "high",
                    "evidence_refs": ["synthetic-record-capture"],
                }
            ],
            evidence_sources=[
                SurfaceEvidence(source="synthetic-discovery", reference="synthetic-run")
            ],
        )
        return {"canonical_attack_surface": surface.model_dump(mode="json")}


def test_parser_accepts_bounded_live_command(tmp_path):
    args = cli_args(tmp_path, "--trace")
    assert args.target_class == "dedicated_lab"
    assert args.request_budget == 30
    assert args.trace is True


def test_model_configuration_preserves_repository_provider_values():
    configuration = research_cli._model_configuration(
        "ollama",
        "explicit-local-model",
        environ={
            "MODEL_DEFAULT_PROVIDER": "ollama",
            "MODEL_TIMEOUT_SECONDS": "120",
            "MODEL_MAX_OUTPUT_TOKENS": "3072",
            "OLLAMA_BASE_URL": "http://127.0.0.1:11555",
            "P3_OLLAMA_MODEL": "repository-model",
        },
    )
    assert configuration.ollama.model_name == "explicit-local-model"
    assert configuration.ollama.timeout_seconds == 120
    assert configuration.ollama.max_output_tokens == 3072
    assert configuration.ollama.base_url == "http://127.0.0.1:11555"


def test_model_configuration_uses_repository_model_without_cli_override():
    configuration = research_cli._model_configuration(
        "ollama",
        None,
        environ={"P3_OLLAMA_MODEL": "repository-model"},
    )
    assert configuration.ollama.model_name == "repository-model"


def test_explicit_model_limits_override_repository_values_without_dropping_base_url():
    configuration = research_cli._model_configuration(
        "ollama",
        "explicit-local-model",
        environ={
            "MODEL_TIMEOUT_SECONDS": "120",
            "MODEL_MAX_OUTPUT_TOKENS": "3072",
            "OLLAMA_BASE_URL": "http://127.0.0.1:11555",
        },
        timeout_seconds=180,
        max_output_tokens=2048,
    )
    assert configuration.ollama.timeout_seconds == 180
    assert configuration.ollama.max_output_tokens == 2048
    assert configuration.ollama.base_url == "http://127.0.0.1:11555"


def test_parser_rejects_non_enum_target_class(tmp_path):
    values = [
        "run",
        "--target",
        TARGET,
        "--target-class",
        "laboratory",
        "--research-id",
        "invalid-target-class",
        "--read-only",
        "--database",
        str(tmp_path / "research.sqlite3"),
    ]
    with pytest.raises(SystemExit):
        research_cli.build_parser().parse_args(values)


def test_controlled_tokens_enter_vault_and_only_references_enter_context():
    with CredentialVault() as vault:
        context = research_cli.controlled_context_from_environment(
            vault, controlled_environment()
        )
        assert [item.account_id for item in context.accounts] == ["alice", "bob"]
        assert all(item.role == "user" for item in context.accounts)
        references = [item.credential_references["token"] for item in context.accounts]
        assert all(reference.startswith("cred_") for reference in references)
        assert all(vault.contains(reference) for reference in references)
        assert vault.get(references[0]) == f"Bearer {SYNTHETIC_SECRET}"
        assert SYNTHETIC_SECRET not in context.model_dump_json()


def test_controlled_account_configuration_errors_are_secret_free():
    with CredentialVault() as vault:
        with pytest.raises(research_cli.ResearchCLIError) as caught:
            research_cli.controlled_context_from_environment(
                vault,
                {
                    "CYBERCORTEX_ACCOUNT_A_ID": "alice",
                    "UNRELATED_SECRET": SYNTHETIC_SECRET,
                },
            )
    assert SYNTHETIC_SECRET not in str(caught.value)


def test_read_only_policy_is_exact_and_conservative():
    with CredentialVault() as vault:
        context = research_cli.controlled_context_from_environment(
            vault, controlled_environment()
        )
        policy = research_cli.build_assessment_policy(
            target=TARGET,
            research_id="policy-test",
            request_budget=30,
            controlled_context=context,
        )
    assert policy.authorization_confirmed is True
    assert policy.allowed_methods == ["GET", "HEAD", "OPTIONS"]
    assert policy.credentials_allowed is True
    assert policy.controlled_account_ids == ["alice", "bob"]
    assert policy.allow_state_changes is False
    assert policy.require_test_owned_resources is True
    assert policy.require_cleanup_for_state_changes is True
    assert policy.oast_allowed is False
    assert policy.allow_bounded_rate_limit_verification is False
    assert policy.requests_per_second == 2
    assert policy.max_concurrency == 1
    assert policy.allowed_assets[0].value == TARGET
    assert policy.allowed_assets[0].ports == [443]


def test_cli_policy_reference_is_neutral_stable_and_authorizable():
    fixture = build_runtime_fixture()
    state = fixture.gate.state
    target = state.targets[0].canonical_reference
    controlled = fixture.gate.controlled_context
    policy = research_cli.build_assessment_policy(
        target=target,
        research_id=state.research_id,
        request_budget=fixture.budget.limit,
        controlled_context=controlled,
    )
    equivalent = research_cli.build_assessment_policy(
        target=target,
        research_id=state.research_id,
        request_budget=fixture.budget.limit,
        controlled_context=controlled.model_copy(
            update={"accounts": tuple(reversed(controlled.accounts))}
        ),
    )
    changed = research_cli.build_assessment_policy(
        target=target,
        research_id=state.research_id,
        request_budget=fixture.budget.limit - 1,
        controlled_context=controlled,
    )
    assert re.fullmatch(r"policy_[0-9a-f]{16}", policy.authorization_reference)
    assert equivalent.authorization_reference == policy.authorization_reference
    assert changed.authorization_reference != policy.authorization_reference
    reject_secret_material(policy.authorization_reference, location="policy reference")

    context = fixture.gate.compiler_context.model_copy(
        update={"policy_reference": policy.authorization_reference}
    )
    experiment = ExperimentCompiler(context=context).compile(
        object_proposal(), state, context
    )
    calls = []

    def requester(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("authorization must not invoke transport")

    transport = ScopedHTTPClient(
        policy=policy,
        budget=fixture.budget,
        requester=requester,
        max_response_bytes=100_000,
    )
    gate = ResearchExecutionGate(
        state=state,
        policy=policy,
        controlled_context=controlled,
        vault=fixture.vault,
        budget=fixture.budget,
        transport=transport,
        compiler_context=context,
        request_templates=tuple(fixture.gate.request_templates.values()),
        controlled_values=tuple(fixture.gate.controlled_values.values()),
        evidence_summaries=tuple(fixture.gate.evidence_summaries.values()),
        state_snapshots=tuple(fixture.gate.state_snapshots.values()),
        scope_reference=state.targets[0].scope_reference,
        current_time=fixture.gate.current_time,
    )

    authorization = gate.authorize(experiment)

    assert authorization.experiment is experiment
    assert authorization.policy_reference == policy.authorization_reference
    assert calls == []


def test_wiring_shares_one_request_budget_and_is_local_only(tmp_path):
    args = cli_args(tmp_path, "--dry-run")
    with CredentialVault() as vault:
        context = research_cli.controlled_context_from_environment(
            vault, controlled_environment()
        )
        wiring = research_cli.build_wiring(
            args,
            vault=vault,
            controlled_context=context,
            tracer=research_cli.SafeTracer(False, io.StringIO()),
        )
        budget = wiring.request_budget
        assert wiring.bootstrapper.request_budget is budget
        assert wiring.bootstrapper.tool_runner.request_budget is budget
        assert wiring.bootstrapper.tool_runner.http_client.budget is budget
        assert wiring.transport.budget is budget
        assert wiring.budget_manager.request_budget is budget
        orchestrator = research_cli._build_orchestrator(wiring, wiring.state)
        assert orchestrator.gate.budget is budget
        assert orchestrator.runtime.budget is budget
        assert wiring.routing_policy.mode.value == "local_only"
        assert wiring.routing_policy.preferred.provider == "ollama"
        assert wiring.routing_policy.fallback_allowed is False
        assert wiring.routing_policy.max_provider_attempts == 1
        assert wiring.bootstrapper.limits.maximum_discovery_target_requests == 30
        assert wiring.bootstrapper.limits.maximum_bootstrap_model_calls == 1


def test_wiring_aligns_reasoning_and_provider_output_ceilings(tmp_path):
    args = cli_args(tmp_path, "--dry-run")
    with CredentialVault() as vault:
        wiring = research_cli.build_wiring(
            args,
            vault=vault,
            controlled_context=research_cli.ControlledContext(),
            tracer=research_cli.SafeTracer(False, io.StringIO()),
            environ={
                "MODEL_TIMEOUT_SECONDS": "120",
                "MODEL_MAX_OUTPUT_TOKENS": "3072",
                "OLLAMA_BASE_URL": "http://127.0.0.1:11555",
            },
        )
        provider = wiring.reasoning_engine.router.registry.create("ollama")
    assert wiring.reasoning_engine.max_output_tokens == 3072
    assert provider.configuration.max_output_tokens == 3072
    assert provider.configuration.timeout_seconds == 120


def test_new_run_contains_only_registered_target_before_bootstrap(tmp_path):
    args = cli_args(tmp_path, "--dry-run")
    with CredentialVault() as vault:
        wiring = research_cli.build_wiring(
            args,
            vault=vault,
            controlled_context=research_cli.ControlledContext(),
            tracer=research_cli.SafeTracer(False, io.StringIO()),
        )
        state = wiring.state
    assert len(state.targets) == 1
    assert state.targets[0].canonical_reference == TARGET
    assert not state.surfaces
    assert not state.endpoints
    assert not state.parameters
    assert not state.request_templates
    assert not state.hypotheses


def test_dry_run_makes_zero_calls_and_secret_never_reaches_outputs_or_database(
    tmp_path, capsys
):
    database = tmp_path / "dry-run.sqlite3"
    result = research_cli.main(
        [
            "run",
            "--target",
            TARGET,
            "--target-class",
            "dedicated_lab",
            "--research-id",
            "dry-secret-test",
            "--read-only",
            "--dry-run",
            "--database",
            str(database),
        ],
        environ=controlled_environment(),
    )
    captured = capsys.readouterr()
    assert result == 0
    assert '"total_requests": 0' in captured.out
    assert '"attempted_calls": 0' in captured.out
    assert SYNTHETIC_SECRET not in captured.out
    assert SYNTHETIC_SECRET not in captured.err
    assert SYNTHETIC_SECRET.encode() not in database.read_bytes()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(database) + suffix)
        if sidecar.exists():
            assert SYNTHETIC_SECRET.encode() not in sidecar.read_bytes()


def test_bootstrap_packet_state_and_contracts_exclude_raw_tokens(tmp_path):
    args = cli_args(tmp_path)
    with CredentialVault() as vault:
        context = research_cli.controlled_context_from_environment(
            vault, controlled_environment()
        )
        wiring = research_cli.build_wiring(
            args,
            vault=vault,
            controlled_context=context,
            tracer=research_cli.SafeTracer(False, io.StringIO()),
        )
        runner = FakeDiscoveryRunner(wiring.request_budget)
        wiring.bootstrapper.tool_runner = runner
        wiring.bootstrapper.reasoning_engine = None
        wiring.bootstrapper.routing_policy = None
        wiring.bootstrapper.packet_builder = None
        state = wiring.bootstrapper.prepare(wiring.state)
        packet = PublicSafeResearchPacketBuilder(
            wiring.compiler.registry, wiring.budget_manager
        ).build(state)
        serialized_state = state.model_dump_json()
        serialized_packet = packet.model_dump_json()
        database_bytes = Path(args.database).read_bytes()
    proposal = object_proposal()
    compiler_state = compiler_state_fixture.__wrapped__()
    compiler_context = compiler_context_fixture.__wrapped__()
    experiment = ExperimentCompiler().compile(
        proposal, compiler_state, compiler_context
    )
    for serialized in (
        serialized_state,
        serialized_packet,
        proposal.model_dump_json(),
        experiment.model_dump_json(),
        database_bytes.decode("utf-8", errors="ignore"),
    ):
        assert SYNTHETIC_SECRET not in serialized
    assert runner.calls == 1
    assert len(state.identities) == 2
    assert len(state.token_refs) == 2


def test_safe_trace_ignores_errors_and_never_echoes_secret():
    stream = io.StringIO()
    tracer = research_cli.SafeTracer(True, stream)
    tracer.tool_status(
        "synthetic-tool",
        {"status": "failed", "error": SYNTHETIC_SECRET},
    )
    tracer.emit("STOP", status="stopped", reason="bounded_stop")
    rendered = stream.getvalue()
    assert "DISCOVERY" in rendered
    assert "STOP" in rendered
    assert SYNTHETIC_SECRET not in rendered


def test_resume_loads_state_without_repeating_or_refunding_budgets(tmp_path):
    database = tmp_path / "resume.sqlite3"
    first = [
        "run",
        "--target",
        TARGET,
        "--target-class",
        "dedicated_lab",
        "--research-id",
        "resume-test",
        "--read-only",
        "--dry-run",
        "--database",
        str(database),
    ]
    assert research_cli.main(first, environ={}) == 0
    output = io.StringIO()
    errors = io.StringIO()
    resumed = research_cli.main(
        [
            "run",
            "--resume",
            "resume-test",
            "--read-only",
            "--dry-run",
            "--database",
            str(database),
        ],
        environ={},
        stdout=output,
        stderr=errors,
    )
    assert resumed == 0
    summary = json.loads(output.getvalue())
    assert summary["research_id"] == "resume-test"
    assert summary["request_usage"]["total_requests"] == 0
    assert summary["model_usage"]["attempted_calls"] == 0
    assert errors.getvalue() == ""


def test_model_ledger_restores_usage_without_fabricating_records():
    ledger = ModelCallLedger()
    prior = ModelUsageDelta(
        attempted_calls=2,
        successful_calls=2,
        input_tokens=20,
        output_tokens=10,
        total_tokens=30,
    )
    ledger.restore_run_usage("resume-ledger", prior)
    assert ledger.records == ()
    assert ledger.usage_for_run("resume-ledger") == prior
    before = ledger.snapshot(run_id="resume-ledger")
    ledger.record_pre_call_failure(
        provider="ollama",
        model="local-test-model",
        latency_seconds=0.0,
        task_type="research_strategy",
        run_id="resume-ledger",
        hypothesis_id=None,
        fallback_depth=0,
        outcome=ModelErrorCode.configuration_error,
    )
    after = ledger.snapshot(run_id="resume-ledger")
    assert after.usage.attempted_calls == 3
    assert ledger.delta(before, after).attempted_calls == 1


def test_production_cli_has_no_target_or_weakness_hints():
    source = Path(research_cli.__file__).read_text(encoding="utf-8").casefold()
    forbidden = (
        "/api/" + "projects",
        "project" + "_id",
        "p-" + "1042",
        "p-" + "2087",
        "bo" + "la",
        "id" + "or",
        "object " + "authorization",
        "known " + "vulnerability",
    )
    assert all(value not in source for value in forbidden)


def test_safe_failure_does_not_echo_vaulted_token(tmp_path):
    output = io.StringIO()
    errors = io.StringIO()
    result = research_cli.main(
        [
            "run",
            "--target",
            "not-a-url",
            "--target-class",
            "dedicated_lab",
            "--research-id",
            "safe-error-test",
            "--read-only",
            "--dry-run",
            "--database",
            str(tmp_path / "safe-error.sqlite3"),
        ],
        environ=controlled_environment(),
        stdout=output,
        stderr=errors,
    )
    assert result == 2
    assert SYNTHETIC_SECRET not in output.getvalue()
    assert SYNTHETIC_SECRET not in errors.getvalue()
