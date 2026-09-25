"""
testbed/runner/batch.py
=======================
Automated PCAP Generation & Batch Orchestration (Fix #4).

Pipelines:
    Scenario Matrix (126 rows)
          ↓
    Scenario Selection (all 126 or specified subset, canonical order)
          ↓
    Dependency-Aware Preflight (Postfix, Dovecot, and/or MITM based on needs)
          ↓
    For each selected scenario:
      1. Check Resume against prior coherent run_id (skip only if fully verified)
      2. Pre-classification Stale Artifact Cleanup (.pcap, .expected, .observed, .comparison, .evidence, .batch)
      3. Classify Scenario (EXECUTABLE_STANDARD, BLOCKED, UNRESOLVABLE, SPECIAL_HARNESS)
      4. Execute only if eligible (EXECUTABLE_STANDARD):
         Stage → Deploy → Capture → Client → Offline Forensics → Validation → Hash & Manifest
          ↓
    Fault-Isolated Sequential Execution (scenario failure does not abort batch)
          ↓
    Batch Generation Report & Manifest (batch_run_<run_id>.json, batch_report.json, batch_report.md)
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

import jsonschema

# Ensure project root is in sys.path
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from testbed.runner.comparator import compare
from testbed.runner.resolver import (
    ResolutionStatus,
    TLSCipherResolver,
    UnresolvableScenarioError,
)
from testbed.runner.runner import (
    ScenarioExecutionResult,
    ScenarioRunner,
    StaleArtifactCleanupError,
    cleanup_scenario_artifacts,
    discover_docker_bridge,
)
from testbed.runner.scenario_contract import (
    CipherMode,
    GenerationMode,
    ScenarioContract,
    load_scenario_contracts,
    validate_scenario_contracts,
)
from testbed.runner.spec import ScenarioSpec, load_matrix


class PreflightError(RuntimeError):
    """Raised when environment or dependency preflight checks fail."""
    pass


class ResumeError(RuntimeError):
    """Raised when batch resume cannot find or validate a prior run."""
    pass


class BatchExecutionCategory(str, Enum):
    """Classification of scenarios for batch orchestration."""
    EXECUTABLE_STANDARD = "EXECUTABLE_STANDARD"
    BLOCKED = "BLOCKED"
    UNRESOLVABLE = "UNRESOLVABLE"
    SPECIAL_HARNESS = "SPECIAL_HARNESS"


class ScenarioExecutionState(str, Enum):
    """Execution state of a scenario within a batch run."""
    GENERATED = "GENERATED"
    BLOCKED = "BLOCKED"
    UNRESOLVABLE = "UNRESOLVABLE"
    SPECIAL_HARNESS = "SPECIAL_HARNESS"
    FAILED = "FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class ScenarioClassification:
    """Classification decision and metadata for a scenario."""
    scenario_id: str
    category: BatchExecutionCategory
    reason: Optional[str] = None
    resolver_status: Optional[str] = None
    selected_cipher: Optional[str] = None


@dataclass
class ScenarioBatchRecord:
    """Persistent execution record for a scenario in a batch run."""
    scenario_id: str
    protocol: str
    category: str
    execution_state: str
    comparison_status: Optional[str] = None
    selected_cipher: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None
    artifacts: Dict[str, str] = field(default_factory=dict)
    artifact_hashes: Optional[Dict[str, str]] = None
    completed_at: Optional[str] = None
    resumed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_file_sha256(path: Path) -> str:
    """Compute sha256 hex digest for a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def check_preflight(
    selected_specs: List[ScenarioSpec],
    contracts: Dict[str, ScenarioContract],
    captures_dir: Path,
    active_dir: Path,
    network_name: str = "testbed_mailtest_net",
) -> Dict[str, Any]:
    """
    Dependency-aware preflight validation.
    Determines required containers and network services strictly from the scenarios
    actually selected for execution.
    """
    preflight_info: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "required_services": [],
        "active_containers": [],
        "bridge_interface": None,
        "tshark_path": None,
    }

    # 1. Check docker executable
    docker_bin = shutil.which("docker")
    if not docker_bin:
        raise PreflightError("Docker executable 'docker' not found in PATH")

    # 2. Determine container dependencies based on selected scenarios
    requires_smtp = any(s.is_smtp for s in selected_specs)
    requires_dovecot = any(s.is_imap or s.is_pop3 for s in selected_specs)
    requires_mitm = any(
        contracts.get(s.scenario_id) is not None
        and contracts[s.scenario_id].special_harness == "mitm_starttls_strip"
        for s in selected_specs
    )
    requires_legacy = any(
        s.scenario_id in ("PCAP-083", "PCAP-084")
        for s in selected_specs
    )

    required_containers: List[str] = []
    if requires_smtp:
        required_containers.append("mailtest-postfix")
    if requires_dovecot:
        required_containers.append("mailtest-dovecot")
    if requires_mitm:
        required_containers.append("mailtest-mitm")
    if requires_legacy:
        required_containers.append("mailtest-legacy")

    preflight_info["required_services"] = required_containers

    # 3. Check running docker containers
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        running = set(line.strip() for line in proc.stdout.splitlines() if line.strip())
        preflight_info["active_containers"] = sorted(list(running))
    except Exception as exc:
        raise PreflightError(f"Failed to query running Docker containers: {exc}")

    missing_containers = [c for c in required_containers if c not in running]
    if missing_containers:
        raise PreflightError(
            f"Required container(s) not running for selected scenarios: {missing_containers}. "
            f"Active containers: {sorted(list(running))}"
        )

    # 4. Check bridge interface and network if any scenarios require live network
    if required_containers:
        try:
            bridge_iface = discover_docker_bridge(network_name)
            preflight_info["bridge_interface"] = bridge_iface
        except Exception as exc:
            raise PreflightError(f"Preflight bridge discovery failed: {exc}")

        # 5. Check tshark executable
        tshark_bin = shutil.which("tshark")
        if not tshark_bin:
            raise PreflightError("tshark executable not found in PATH")
        preflight_info["tshark_path"] = tshark_bin

    # 6. Check writable directories
    for name, p in (("captures_dir", captures_dir), ("active_dir", active_dir)):
        p.mkdir(parents=True, exist_ok=True)
        test_file = p / f".preflight_write_test_{uuid.uuid4().hex[:8]}"
        try:
            test_file.write_text("ok")
            test_file.unlink()
        except OSError as exc:
            raise PreflightError(f"Directory '{name}' ({p}) is not writable: {exc}")

    # 7. Check schemas and contract validity
    contract_errors = validate_scenario_contracts(contracts, expected_count=len(contracts))
    if contract_errors:
        raise PreflightError(f"Scenario contracts validation failed: {'; '.join(contract_errors[:5])}")

    return preflight_info


def classify_scenario(
    spec: ScenarioSpec,
    contract: ScenarioContract,
    resolver: TLSCipherResolver,
) -> ScenarioClassification:
    """
    Deterministic classification of a single scenario:
    - EXECUTABLE_STANDARD: standard Postfix/Dovecot scenario resolvable to configurable cipher or cleartext.
    - BLOCKED: standard scenario blocked by daemon limitation (DAEMON_CANNOT_ENFORCE).
    - UNRESOLVABLE: contradictory matrix intent or oracle inconsistency.
    - SPECIAL_HARNESS: requires dedicated harness outside standard daemon runner.
    """
    sid = spec.scenario_id

    if contract.generation_mode == GenerationMode.UNRESOLVABLE:
        return ScenarioClassification(
            scenario_id=sid,
            category=BatchExecutionCategory.UNRESOLVABLE,
            reason=contract.unresolvable_reason or "Matrix oracle inconsistent",
        )

    if contract.generation_mode == GenerationMode.DEDICATED_HARNESS:
        return ScenarioClassification(
            scenario_id=sid,
            category=BatchExecutionCategory.SPECIAL_HARNESS,
            reason=f"Dedicated harness: {contract.special_harness} ({contract.harness_status})",
        )

    if contract.generation_mode == GenerationMode.STANDARD:
        resolution = resolver.resolve(spec)
        res_status = resolution.cipher_resolution_status
        if res_status in (
            ResolutionStatus.CONFIGURABLE_CANDIDATE_SELECTED,
            ResolutionStatus.NOT_APPLICABLE,
        ):
            return ScenarioClassification(
                scenario_id=sid,
                category=BatchExecutionCategory.EXECUTABLE_STANDARD,
                resolver_status=res_status.value,
                selected_cipher=resolution.selected_cipher,
            )
        elif res_status == ResolutionStatus.DAEMON_CANNOT_ENFORCE:
            return ScenarioClassification(
                scenario_id=sid,
                category=BatchExecutionCategory.BLOCKED,
                reason=resolution.reason or "Daemon cannot enforce cipher suite",
                resolver_status=res_status.value,
                selected_cipher=resolution.selected_cipher,
            )
        else:
            return ScenarioClassification(
                scenario_id=sid,
                category=BatchExecutionCategory.UNRESOLVABLE,
                reason=resolution.reason or f"Resolver status: {res_status.value}",
                resolver_status=res_status.value,
            )

    return ScenarioClassification(
        scenario_id=sid,
        category=BatchExecutionCategory.UNRESOLVABLE,
        reason=f"Unknown generation mode: {contract.generation_mode}",
    )


def verify_scenario_artifacts(
    captures_dir: Path,
    scenario_id: str,
    expected_schema: Dict[str, Any],
    observed_schema: Dict[str, Any],
    comparison_schema: Dict[str, Any],
) -> Tuple[bool, Optional[str], Optional[Dict[str, str]]]:
    """
    Verify the complete set of generation artifacts for a scenario:
    1. .pcap exists and is non-empty.
    2. .expected.json exists, valid JSON, matches schema and scenario_id.
    3. .observed.json exists, valid JSON, matches schema and scenario_id.
    4. .comparison.json exists, valid JSON, matches schema and scenario_id.
    5. .evidence.json exists, valid JSON, is a non-empty dictionary.
    Returns (is_valid, error_message, artifact_hashes).
    """
    pcap_path = captures_dir / f"{scenario_id}.pcap"
    expected_path = captures_dir / f"{scenario_id}.expected.json"
    observed_path = captures_dir / f"{scenario_id}.observed.json"
    comparison_path = captures_dir / f"{scenario_id}.comparison.json"
    evidence_path = captures_dir / f"{scenario_id}.evidence.json"

    # 1. PCAP verification
    if not pcap_path.exists():
        return False, f"PCAP artifact {pcap_path.name} does not exist", None
    if pcap_path.stat().st_size == 0:
        return False, f"PCAP artifact {pcap_path.name} is empty (0 bytes)", None

    # 2. JSON artifacts existence & schema validation
    json_targets = [
        (expected_path, expected_schema, "expected"),
        (observed_path, observed_schema, "observed"),
        (comparison_path, comparison_schema, "comparison"),
    ]

    for file_path, schema, label in json_targets:
        if not file_path.exists():
            return False, f"{label.capitalize()} artifact {file_path.name} does not exist", None
        try:
            data = json.loads(file_path.read_text())
        except Exception as exc:
            return False, f"{label.capitalize()} artifact {file_path.name} is invalid JSON: {exc}", None

        if data.get("scenario_id") != scenario_id:
            return (
                False,
                f"{label.capitalize()} artifact scenario_id '{data.get('scenario_id')}' != '{scenario_id}'",
                None,
            )

        try:
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as val_err:
            return False, f"{label.capitalize()} artifact schema violation: {val_err.message}", None

    # 3. Evidence artifact check
    if not evidence_path.exists():
        return False, f"Evidence artifact {evidence_path.name} does not exist", None
    try:
        evidence_data = json.loads(evidence_path.read_text())
        if not isinstance(evidence_data, dict) or not evidence_data:
            return False, f"Evidence artifact {evidence_path.name} is not a valid non-empty JSON object", None
    except Exception as exc:
        return False, f"Evidence artifact {evidence_path.name} is invalid JSON: {exc}", None

    # Compute SHA-256 for all 5 artifacts
    hashes = {
        "pcap": compute_file_sha256(pcap_path),
        "expected": compute_file_sha256(expected_path),
        "observed": compute_file_sha256(observed_path),
        "comparison": compute_file_sha256(comparison_path),
        "evidence": compute_file_sha256(evidence_path),
    }

    return True, None, hashes


class BatchOrchestrator:
    """
    Deterministic batch generation orchestrator for testbed scenarios.
    """

    def __init__(
        self,
        matrix_path: Optional[Path] = None,
        contracts_path: Optional[Path] = None,
        captures_dir: Optional[Path] = None,
        active_dir: Optional[Path] = None,
        schemas_dir: Optional[Path] = None,
    ):
        self.matrix_path = matrix_path or (_project_root / "data" / "pcap_generation_matrix.csv")
        self.contracts_path = contracts_path or (_project_root / "data" / "scenario_contracts.json")
        self.captures_dir = captures_dir or (_project_root / "testbed" / "captures")
        self.active_dir = active_dir or (_project_root / "testbed" / "active")
        schemas_dir = schemas_dir or (_project_root / "data")

        self.expected_schema = json.loads((schemas_dir / "expected_schema.json").read_text())
        self.observed_schema = json.loads((schemas_dir / "observed_schema.json").read_text())
        self.comparison_schema = json.loads((schemas_dir / "comparison_schema.json").read_text())

        # Authoritative data
        self.specs_by_id = {s.scenario_id: s for s in load_matrix(str(self.matrix_path))}
        self.matrix_order = list(self.specs_by_id.keys())
        self.contracts = load_scenario_contracts(str(self.contracts_path))
        self.resolver = TLSCipherResolver(contracts=self.contracts)

        self._runner: Optional[ScenarioRunner] = None

    @property
    def runner(self) -> ScenarioRunner:
        if self._runner is None:
            self._runner = ScenarioRunner(
                captures_dir=self.captures_dir,
                active_dir=self.active_dir,
            )
        return self._runner

    @runner.setter
    def runner(self, value: ScenarioRunner) -> None:
        self._runner = value

    def select_scenarios(self, requested_ids: Optional[List[str]] = None) -> List[ScenarioSpec]:
        """
        Filter and sort selected scenarios in canonical CSV matrix order.
        """
        if not requested_ids:
            return [self.specs_by_id[sid] for sid in self.matrix_order]

        unknown = [sid for sid in requested_ids if sid not in self.specs_by_id]
        if unknown:
            raise ValueError(f"Unknown scenario ID(s) requested: {unknown}")

        # Canonical matrix ordering preservation
        selected_set = set(requested_ids)
        return [self.specs_by_id[sid] for sid in self.matrix_order if sid in selected_set]

    def _load_run_manifest(self, run_id: str) -> Dict[str, Any]:
        """Load an existing batch run manifest."""
        manifest_path = self.captures_dir / f"batch_run_{run_id}.json"
        if not manifest_path.exists():
            raise ResumeError(f"Run manifest for run_id '{run_id}' not found at {manifest_path}")
        try:
            return json.loads(manifest_path.read_text())
        except Exception as exc:
            raise ResumeError(f"Run manifest '{manifest_path}' is corrupted: {exc}")

    def _resolve_resume_run_id(self, explicit_run_id: Optional[str] = None) -> str:
        """Resolve the prior run_id to resume from."""
        if explicit_run_id:
            return explicit_run_id

        pointer_file = self.captures_dir / "latest_batch_run.json"
        if not pointer_file.exists():
            raise ResumeError(
                "Cannot resume: No prior batch run pointer found (latest_batch_run.json missing). "
                "Specify explicit run_id via --resume <run_id> or run a fresh batch without --resume."
            )
        try:
            pointer = json.loads(pointer_file.read_text())
            run_id = pointer.get("run_id")
            if not run_id:
                raise ValueError("latest_batch_run.json has no 'run_id'")
            return run_id
        except Exception as exc:
            raise ResumeError(f"Failed to read latest batch run pointer: {exc}")

    def _verify_resume_eligibility(
        self,
        scenario_id: str,
        resume_run_id: str,
        resume_manifest: Dict[str, Any],
    ) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        Verify if a scenario can be safely resumed from a prior batch run.
        Requires:
        1. Scenario recorded as GENERATED in prior run manifest for resume_run_id.
        2. <scenario_id>.batch.json exists and matches resume_run_id.
        3. All 5 artifacts exist, pass schemas, and match recorded SHA-256 hashes.
        """
        scenarios_record = resume_manifest.get("scenarios", {})
        prior_record = scenarios_record.get(scenario_id)
        if not prior_record or prior_record.get("execution_state") != ScenarioExecutionState.GENERATED.value:
            return False, None

        batch_meta_path = self.captures_dir / f"{scenario_id}.batch.json"
        if not batch_meta_path.exists():
            return False, None

        try:
            meta = json.loads(batch_meta_path.read_text())
            if meta.get("run_id") != resume_run_id:
                return False, None
            recorded_hashes = meta.get("artifact_hashes") or {}
        except Exception:
            return False, None

        valid, err, computed_hashes = verify_scenario_artifacts(
            captures_dir=self.captures_dir,
            scenario_id=scenario_id,
            expected_schema=self.expected_schema,
            observed_schema=self.observed_schema,
            comparison_schema=self.comparison_schema,
        )
        if not valid or not computed_hashes:
            return False, None

        if computed_hashes != recorded_hashes:
            return False, None

        return True, computed_hashes

    def run_batch(
        self,
        requested_ids: Optional[List[str]] = None,
        resume: bool = False,
        resume_run_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute the automated batch generation process.
        """
        selected_specs = self.select_scenarios(requested_ids)
        selected_ids = [s.scenario_id for s in selected_specs]

        # 1. Dependency-aware Preflight
        preflight_info = check_preflight(
            selected_specs=selected_specs,
            contracts=self.contracts,
            captures_dir=self.captures_dir,
            active_dir=self.active_dir,
        )

        # 2. Dry run handling
        if dry_run:
            classifications: Dict[str, Any] = {}
            for s in selected_specs:
                c = self.contracts[s.scenario_id]
                cl = classify_scenario(s, c, self.resolver)
                classifications[s.scenario_id] = {
                    "protocol": s.protocol,
                    "category": cl.category.value,
                    "selected_cipher": cl.selected_cipher,
                    "reason": cl.reason,
                }
            return {
                "dry_run": True,
                "preflight": preflight_info,
                "total_selected": len(selected_specs),
                "classifications": classifications,
            }

        # 3. Initialize Run State and Run ID
        start_time = datetime.now(timezone.utc)
        target_resume_id: Optional[str] = None
        prior_manifest: Optional[Dict[str, Any]] = None

        if resume:
            target_resume_id = self._resolve_resume_run_id(resume_run_id)
            prior_manifest = self._load_run_manifest(target_resume_id)
            run_id = target_resume_id
        else:
            run_id = f"batch_{start_time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        manifest_path = self.captures_dir / f"batch_run_{run_id}.json"
        latest_pointer_path = self.captures_dir / "latest_batch_run.json"

        # Initialize scenario records
        records: Dict[str, ScenarioBatchRecord] = {}
        if prior_manifest:
            for sid, rec in prior_manifest.get("scenarios", {}).items():
                if sid in self.specs_by_id:
                    records[sid] = ScenarioBatchRecord(**rec)

        def save_state(status: str = "IN_PROGRESS") -> None:
            now_iso = datetime.now(timezone.utc).isoformat()
            state = {
                "run_id": run_id,
                "status": status,
                "started_at": start_time.isoformat(),
                "updated_at": now_iso,
                "preflight": preflight_info,
                "scenarios": {sid: rec.to_dict() for sid, rec in records.items()},
            }
            manifest_path.write_text(json.dumps(state, indent=2))
            latest_pointer_path.write_text(json.dumps({"run_id": run_id, "updated_at": now_iso}, indent=2))

        save_state("IN_PROGRESS")

        # 4. Sequential Orchestration Loop
        for spec in selected_specs:
            sid = spec.scenario_id
            contract = self.contracts[sid]

            # Step 1: Check Resume eligibility if resume requested
            if resume and target_resume_id and prior_manifest:
                is_eligible, hashes = self._verify_resume_eligibility(sid, target_resume_id, prior_manifest)
                if is_eligible:
                    rec = records.get(sid)
                    if rec:
                        rec.resumed = True
                    save_state("IN_PROGRESS")
                    continue

            # Step 2: Pre-classification Stale-Artifact Cleanup
            try:
                cleanup_scenario_artifacts(self.captures_dir, sid)
            except StaleArtifactCleanupError as clean_err:
                records[sid] = ScenarioBatchRecord(
                    scenario_id=sid,
                    protocol=spec.protocol,
                    category=BatchExecutionCategory.EXECUTABLE_STANDARD.value,
                    execution_state=ScenarioExecutionState.CLEANUP_FAILED.value,
                    error=str(clean_err),
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
                save_state("IN_PROGRESS")
                continue

            # Step 3: Classify Scenario
            classification = classify_scenario(spec, contract, self.resolver)

            if classification.category == BatchExecutionCategory.BLOCKED:
                records[sid] = ScenarioBatchRecord(
                    scenario_id=sid,
                    protocol=spec.protocol,
                    category=classification.category.value,
                    execution_state=ScenarioExecutionState.BLOCKED.value,
                    selected_cipher=classification.selected_cipher,
                    error=classification.reason,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
                save_state("IN_PROGRESS")
                continue

            if classification.category == BatchExecutionCategory.UNRESOLVABLE:
                records[sid] = ScenarioBatchRecord(
                    scenario_id=sid,
                    protocol=spec.protocol,
                    category=classification.category.value,
                    execution_state=ScenarioExecutionState.UNRESOLVABLE.value,
                    error=classification.reason,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
                save_state("IN_PROGRESS")
                continue

            if classification.category == BatchExecutionCategory.SPECIAL_HARNESS:
                if contract.harness_status != "IMPLEMENTED":
                    records[sid] = ScenarioBatchRecord(
                        scenario_id=sid,
                        protocol=spec.protocol,
                        category=classification.category.value,
                        execution_state=ScenarioExecutionState.SPECIAL_HARNESS.value,
                        error=classification.reason,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                    )
                    save_state("IN_PROGRESS")
                    continue

            # Step 4: Execute Eligible Scenario (EXECUTABLE_STANDARD)
            scenario_start = time.time()
            try:
                result = self.runner.run_scenario(spec)
                scenario_duration = time.time() - scenario_start

                if not result.execution_success:
                    err_text = result.error or "Scenario runner returned unsuccessful execution"
                    records[sid] = ScenarioBatchRecord(
                        scenario_id=sid,
                        protocol=spec.protocol,
                        category=classification.category.value,
                        execution_state=ScenarioExecutionState.FAILED.value,
                        selected_cipher=classification.selected_cipher,
                        duration_seconds=round(scenario_duration, 3),
                        error=err_text,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                    )
                    save_state("IN_PROGRESS")
                    continue

                # Immediate post-execution artifact verification
                is_valid, val_err, hashes = verify_scenario_artifacts(
                    captures_dir=self.captures_dir,
                    scenario_id=sid,
                    expected_schema=self.expected_schema,
                    observed_schema=self.observed_schema,
                    comparison_schema=self.comparison_schema,
                )

                if not is_valid or not hashes:
                    records[sid] = ScenarioBatchRecord(
                        scenario_id=sid,
                        protocol=spec.protocol,
                        category=classification.category.value,
                        execution_state=ScenarioExecutionState.FAILED.value,
                        selected_cipher=classification.selected_cipher,
                        duration_seconds=round(scenario_duration, 3),
                        error=f"Artifact verification failed: {val_err}",
                        completed_at=datetime.now(timezone.utc).isoformat(),
                    )
                    save_state("IN_PROGRESS")
                    continue

                # Associate scenario with current run_id and hashes
                batch_meta = {
                    "run_id": run_id,
                    "scenario_id": sid,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "artifact_hashes": hashes,
                }
                (self.captures_dir / f"{sid}.batch.json").write_text(json.dumps(batch_meta, indent=2))

                artifact_paths = {
                    "pcap": str(self.captures_dir / f"{sid}.pcap"),
                    "expected": str(self.captures_dir / f"{sid}.expected.json"),
                    "observed": str(self.captures_dir / f"{sid}.observed.json"),
                    "comparison": str(self.captures_dir / f"{sid}.comparison.json"),
                    "evidence": str(self.captures_dir / f"{sid}.evidence.json"),
                }

                records[sid] = ScenarioBatchRecord(
                    scenario_id=sid,
                    protocol=spec.protocol,
                    category=classification.category.value,
                    execution_state=ScenarioExecutionState.GENERATED.value,
                    comparison_status=result.comparison_status,
                    selected_cipher=classification.selected_cipher,
                    duration_seconds=round(scenario_duration, 3),
                    artifacts=artifact_paths,
                    artifact_hashes=hashes,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
                save_state("IN_PROGRESS")

            except Exception as exc:
                scenario_duration = time.time() - scenario_start
                records[sid] = ScenarioBatchRecord(
                    scenario_id=sid,
                    protocol=spec.protocol,
                    category=classification.category.value,
                    execution_state=ScenarioExecutionState.FAILED.value,
                    selected_cipher=classification.selected_cipher,
                    duration_seconds=round(scenario_duration, 3),
                    error=f"Unhandled exception during scenario execution: {exc}",
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
                save_state("IN_PROGRESS")

        # 5. Finalize Run and Generate Reports
        end_time = datetime.now(timezone.utc)
        total_duration = (end_time - start_time).total_seconds()
        save_state("COMPLETED")

        report = self.generate_reports(
            run_id=run_id,
            start_time=start_time,
            end_time=end_time,
            total_duration=total_duration,
            preflight_info=preflight_info,
            records=records,
            selected_ids=selected_ids,
        )

        return report

    def generate_reports(
        self,
        run_id: str,
        start_time: datetime,
        end_time: datetime,
        total_duration: float,
        preflight_info: Dict[str, Any],
        records: Dict[str, ScenarioBatchRecord],
        selected_ids: List[str],
    ) -> Dict[str, Any]:
        """
        Generate batch_report.json and batch_report.md in captures_dir.
        """
        # Calculate summary metrics
        counts: Dict[str, int] = {
            "total_selected": len(selected_ids),
            "generated": 0,
            "generated_pass": 0,
            "generated_inconclusive": 0,
            "generated_fail": 0,
            "blocked": 0,
            "unresolvable": 0,
            "special_harness": 0,
            "failed": 0,
            "cleanup_failed": 0,
            "resumed": 0,
        }

        for sid in selected_ids:
            rec = records.get(sid)
            if not rec:
                continue
            if rec.resumed:
                counts["resumed"] += 1

            state = rec.execution_state
            if state == ScenarioExecutionState.GENERATED.value:
                counts["generated"] += 1
                comp = rec.comparison_status
                if comp == "PASS":
                    counts["generated_pass"] += 1
                elif comp == "INCONCLUSIVE":
                    counts["generated_inconclusive"] += 1
                elif comp == "FAIL":
                    counts["generated_fail"] += 1
            elif state == ScenarioExecutionState.BLOCKED.value:
                counts["blocked"] += 1
            elif state == ScenarioExecutionState.UNRESOLVABLE.value:
                counts["unresolvable"] += 1
            elif state == ScenarioExecutionState.SPECIAL_HARNESS.value:
                counts["special_harness"] += 1
            elif state == ScenarioExecutionState.FAILED.value:
                counts["failed"] += 1
            elif state == ScenarioExecutionState.CLEANUP_FAILED.value:
                counts["cleanup_failed"] += 1

        report_data = {
            "run_id": run_id,
            "started_at": start_time.isoformat(),
            "completed_at": end_time.isoformat(),
            "total_duration_seconds": round(total_duration, 2),
            "preflight": preflight_info,
            "summary": counts,
            "scenarios": [records[sid].to_dict() for sid in selected_ids if sid in records],
        }

        # Write batch_report.json
        report_json_path = self.captures_dir / "batch_report.json"
        report_json_path.write_text(json.dumps(report_data, indent=2))

        # Write batch_report.md
        md_lines = [
            f"# Batch Generation Report: `{run_id}`",
            "",
            f"- **Started**: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Completed**: {end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Total Duration**: {total_duration:.2f} seconds",
            f"- **Bridge Interface**: `{preflight_info.get('bridge_interface')}`",
            f"- **Active Containers**: `{', '.join(preflight_info.get('active_containers', []))}`",
            "",
            "## Summary Metrics",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| **Total Selected Scenarios** | **{counts['total_selected']}** |",
            f"| **Successfully Generated** | **{counts['generated']}** |",
            f"| ├─ Comparison PASS | {counts['generated_pass']} |",
            f"| ├─ Comparison INCONCLUSIVE (encrypted certs) | {counts['generated_inconclusive']} |",
            f"| └─ Comparison FAIL | {counts['generated_fail']} |",
            f"| **Blocked by Daemon Limitation** | **{counts['blocked']}** |",
            f"| **Unresolvable (Oracle Inconsistent)** | **{counts['unresolvable']}** |",
            f"| **Dedicated / Special Harness** | **{counts['special_harness']}** |",
            f"| **Failed Executions** | **{counts['failed']}** |",
            f"| **Cleanup Failures** | **{counts['cleanup_failed']}** |",
            f"| **Resumed without re-execution** | **{counts['resumed']}** |",
            "",
            "## Detailed Scenario Execution Matrix",
            "",
            "| Scenario | Protocol | Category | State | Comparison | Selected Cipher | Duration | Details |",
            "|---|---|---|---|---|---|---|---|",
        ]

        for sid in selected_ids:
            rec = records.get(sid)
            if not rec:
                continue
            dur = f"{rec.duration_seconds:.2f}s" if rec.duration_seconds > 0 else "-"
            comp = rec.comparison_status or "-"
            cipher = f"`{rec.selected_cipher}`" if rec.selected_cipher else "-"
            details = rec.error or ("Resumed" if rec.resumed else "OK")
            # Truncate details if overly long
            if len(details) > 80:
                details = details[:77] + "..."
            md_lines.append(
                f"| `{sid}` | {rec.protocol} | {rec.category} | **{rec.execution_state}** | {comp} | {cipher} | {dur} | {details} |"
            )

        md_lines.append("")
        report_md_path = self.captures_dir / "batch_report.md"
        report_md_path.write_text("\n".join(md_lines))

        return report_data


def main() -> None:
    """CLI entrypoint for batch orchestration."""
    import argparse

    parser = argparse.ArgumentParser(description="Automated PCAP Generation & Batch Orchestrator")
    parser.add_argument("scenarios", nargs="*", help="Optional scenario IDs to execute (default: all 126 in canonical order)")
    parser.add_argument("--resume", nargs="?", const="", default=None, help="Resume execution of a prior batch run (optional: specify run_id)")
    parser.add_argument("--dry-run", action="store_true", help="Perform preflight and classification without executing")

    args = parser.parse_args()

    orchestrator = BatchOrchestrator()

    resume_flag = args.resume is not None
    explicit_resume_id = args.resume if (args.resume and args.resume != "") else None

    selected = args.scenarios if args.scenarios else None

    try:
        report = orchestrator.run_batch(
            requested_ids=selected,
            resume=resume_flag,
            resume_run_id=explicit_resume_id,
            dry_run=args.dry_run,
        )

        if args.dry_run:
            print("\n=== DRY RUN SUMMARY ===")
            print(f"Total Selected Scenarios: {report['total_selected']}")
            cats = {}
            for sid, info in report["classifications"].items():
                cat = info["category"]
                cats[cat] = cats.get(cat, 0) + 1
            for cat, count in sorted(cats.items()):
                print(f"  {cat}: {count}")
            print("\nDry run completed successfully.")
            return

        summary = report["summary"]
        print("\n=== BATCH EXECUTION COMPLETE ===")
        print(f"Run ID: {report['run_id']}")
        print(f"Total Duration: {report['total_duration_seconds']:.2f}s")
        print(f"Generated: {summary['generated']} (PASS: {summary['generated_pass']}, INCONCLUSIVE: {summary['generated_inconclusive']}, FAIL: {summary['generated_fail']})")
        print(f"Blocked: {summary['blocked']}")
        print(f"Unresolvable: {summary['unresolvable']}")
        print(f"Special Harness: {summary['special_harness']}")
        print(f"Failed: {summary['failed']}")
        print(f"Reports written to:")
        print(f"  {orchestrator.captures_dir / 'batch_report.json'}")
        print(f"  {orchestrator.captures_dir / 'batch_report.md'}")

        if summary["failed"] > 0 or summary["cleanup_failed"] > 0:
            sys.exit(1)

    except Exception as exc:
        print(f"\n[FATAL BATCH ERROR] {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
