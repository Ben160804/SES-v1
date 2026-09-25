# Batch Generation Report: `batch_test_failure_isolation`

- **Started**: 2026-09-25 22:58:29 UTC
- **Completed**: 2026-09-25 22:58:29 UTC
- **Total Duration**: 2.50 seconds
- **Bridge Interface**: `br-test`
- **Active Containers**: ``

## Summary Metrics

| Metric | Count |
|---|---|
| **Total Selected Scenarios** | **2** |
| **Successfully Generated** | **1** |
| ├─ Comparison PASS | 1 |
| ├─ Comparison INCONCLUSIVE (encrypted certs) | 0 |
| └─ Comparison FAIL | 0 |
| **Blocked by Daemon Limitation** | **0** |
| **Unresolvable (Oracle Inconsistent)** | **0** |
| **Dedicated / Special Harness** | **0** |
| **Failed Executions** | **1** |
| **Cleanup Failures** | **0** |
| **Resumed without re-execution** | **0** |

## Detailed Scenario Execution Matrix

| Scenario | Protocol | Category | State | Comparison | Selected Cipher | Duration | Details |
|---|---|---|---|---|---|---|---|
| `PCAP-004` | SMTP | EXECUTABLE_STANDARD | **FAILED** | - | - | - | Staging failed |
| `PCAP-005` | SMTP | EXECUTABLE_STANDARD | **GENERATED** | PASS | - | 1.23s | OK |
