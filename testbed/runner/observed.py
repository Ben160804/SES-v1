"""
testbed/runner/observed.py
========================
Pure Passive Observation Layer (SecureMailScope Testbed).

Strict Invariant:
- Receives ONLY raw analyzer results (Dict[int, Any]) and scenario_id (for labeling).
- ZERO access to ScenarioSpec, spec.raw_row, matrix CSV, staged config,
  manifest.json, client_result, or generator configuration.
- Preserves ALL streams without flattening or discarding secondary connections.
- Missing or encrypted records (such as TLS 1.3 certificates) remain explicitly
  unobserved / null as emitted by the passive analyzer.
"""

from enum import Enum
from pathlib import Path
from typing import Any, Dict


def serialize_evidence(obj: Any) -> Any:
    """
    Recursively transforms PCAPAnalyzer results into a deterministically JSON-serializable
    representation without information loss:
      - dict keys converted to strings (JSON requirement for integer stream IDs)
      - bytes converted to standard hexadecimal strings
      - datetime / date converted to ISO 8601 UTC strings
      - Enum converted to value (or name if value non-primitive)
      - set / frozenset converted to sorted lists
      - Path converted to str
    """
    if isinstance(obj, dict):
        return {str(k): serialize_evidence(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_evidence(item) for item in obj]
    elif isinstance(obj, (set, frozenset)):
        return sorted([serialize_evidence(item) for item in obj])
    elif isinstance(obj, bytes):
        return obj.hex()
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    elif isinstance(obj, Enum):
        return obj.value if isinstance(obj.value, (str, int, float, bool)) else obj.name
    elif isinstance(obj, Path):
        return str(obj)
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def build_observed_artifact(
    scenario_id: str,
    analyzer_results: Dict[int, Any],
) -> Dict[str, Any]:
    """
    Construct a pure, standalone observed evidence artifact from PCAPAnalyzer results.

    Args:
        scenario_id: Scenario identifier used solely for top-level labeling.
        analyzer_results: The complete dictionary of analyzed streams from PCAPAnalyzer.

    Returns:
        A structured dictionary conforming to data/observed_schema.json preserving
        all streams and underlying analyzer telemetry with zero scenario leakage.
    """
    serialized_sessions = serialize_evidence(analyzer_results)
    formatted_sessions = {}
    for str_id, session in serialized_sessions.items():
        if isinstance(session, dict):
            s_dict = dict(session)
            if "stream_id" not in s_dict:
                try:
                    s_dict["stream_id"] = int(str_id)
                except (ValueError, TypeError):
                    s_dict["stream_id"] = 0
            if "protocol" not in s_dict:
                s_dict["protocol"] = "UNKNOWN"
            for required_field in ("starttls", "tls", "handshake", "certificate"):
                if required_field not in s_dict:
                    s_dict[required_field] = None
            formatted_sessions[str_id] = s_dict
        else:
            formatted_sessions[str_id] = session

    return {
        "schema_version": "1.0",
        "scenario_id": scenario_id,
        "sessions": formatted_sessions,
    }
