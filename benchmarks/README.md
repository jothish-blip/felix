# Felix Permanent Benchmark & Certification System

The Felix Benchmark & Certification System is a permanent, repeatable regression prevention and performance validation framework. It answers the fundamental engineering question:

> **Did Felix actually get better, stay equivalent, or regress after code changes?**

By tracking deterministic security conditions, empirical behavioral bounds, live target trends, request counts, and false-positive/false-negative rates, the benchmark system prevents detection drift, scanning explosions, and false escalation across releases.

---

## Benchmark Corpus Disclaimer

> **Benchmark results are evidence about Felix's behavior on the benchmark corpus, not proof of universal detection accuracy.**
> 
> A score of 0 false positives or 0 false negatives reflects empirical verification against the defined corpus and controlled test fixtures. It does not constitute a universal mathematical guarantee across every arbitrary internet website.

---

## Directory Structure

```text
benchmarks/
├── README.md              # System documentation, guidelines, and certification policies
├── targets/               # Target metadata definitions (JSON)
│   ├── synthetic.json     # Ephemeral in-process deterministic target
│   ├── webjothishanalyst.json # Primary authorized Next.js portfolio target
│   ├── nexspace.json      # Secondary authorized Supabase/SPA target
│   └── example.json       # Minimal baseline control target
├── fixtures/              # Deterministic test cases and synthetic application code
│   ├── secrets/
│   │   ├── true_positives.js   # Controlled credential fixtures
│   │   └── false_positives.js  # Non-secret patterns (UUIDs, nanoid, placeholders)
│   ├── cloud/
│   │   └── mock_configs.js     # Client SDK initialization snippets
│   └── spa/
│       └── app.js              # SPA endpoint interaction routines
├── expected/              # Specification of hard assertions & behavioral bounds
│   ├── synthetic.json
│   ├── webjothishanalyst.json
│   ├── nexspace.json
│   └── example.json
├── results/               # Sanitized benchmark execution summaries (historical & latest)
│   ├── baseline.json      # Reference release baseline
│   └── latest.json        # Latest benchmark execution record
├── scripts/               # Automation scripts
│   └── run-benchmark.ps1  # Cross-platform execution & comparison script
├── main.go                # Benchmark CLI entrypoint
├── runner.go              # Test suite coordinator & certification evaluator
├── synthetic.go           # In-process deterministic HTTP server & auditor
├── live.go                # Bounded live target runner & sanitizer
├── compare.go             # Historical delta comparator
├── types.go               # Benchmark data models and schemas
└── benchmark_test.go      # Go test integration for benchmark assertions
```

---

## Deterministic Certification vs. Live Validation

The benchmark system separates expectations into two complementary domains:

### 1. Deterministic Certification (`DETERMINISTIC`)
- **Authoritative regression signal**: Run against an in-process, ephemeral HTTP test server (`synthetic.go`) serving exact, reproducible fixtures.
- **Strict Hard Assertions**: True-positive detections (AWS keys, GitHub tokens, Slack tokens, Stripe keys, private keys, Supabase service-role keys) must be detected.
- **Suppression Verification**: False-positive candidates (UUIDs, placeholders, CSS rgba, build hashes, nanoid alphabet tables, Supabase anon keys) must yield zero findings.
- **Verification States**: Verifies `VERIFIED`, `DETECTED`, `OBSERVED`, `NOT_VERIFIED`, and `NOT_EXPOSED`.
- **Negative Evidence**: Verifies that 401/403 responses preserve authorization boundaries (`NOT_EXPOSED`) and prevent false escalation.
- **Safety Invariants**: Proves zero HTTP requests are transmitted using `service_role` keys and no destructive HTTP methods are used.

### 2. Live Target Validation (`LIVE`)
- **Trend and Operational Tracking**: Evaluates real-world targets (`webjothishanalyst.site`, `nexspace.space`, `example.com`).
- **Behavioral Bounds**: Uses ranges and tolerances rather than rigid equality (e.g., asset counts, request budgets, duration tolerances).
- **Environmental Resilience**: Prevents real-world website changes (e.g. adding an asset or temporary network latency) from falsely failing build certification.
- **Observational Metrics**: Records exact duration, requests, live asset counts, and informational findings for historical tracking.

---

## Three Categories of Assertions

To prevent benchmark brittleness, expectations are classified into:

| Category | Description | Failure Impact | Example |
| :--- | :--- | :--- | :--- |
| **Hard Assertions** | Security-critical invariants that must remain strictly true. | Immediate **REGRESSION** failure | Exposed `.env` verified; service-role key detected; FP corpus yields 0 findings |
| **Behavioral Bounds** | Operational tolerances for dynamic environments. | Generates **WARNING** (or regression if >100% request growth) | Requests within 10–200; duration < 45s; assets within 10–60 |
| **Observational Metrics** | Environmental metrics recorded for trending. | Logged only; no failure | Exact duration in ms; exact asset count; informational findings count |

---

## How to Run

### Run Full Benchmark Suite (Synthetic + Live Targets)
```powershell
go run ./benchmarks
```
Or using the helper script:
```powershell
.\benchmarks\scripts\run-benchmark.ps1
```

### Run Deterministic Certification Only
For fast local verification during development (zero external network requests):
```powershell
go run ./benchmarks --synthetic-only
```

### Run Live Targets Only
```powershell
go run ./benchmarks --live-only
```

### Save as Reference Baseline
```powershell
go run ./benchmarks --baseline
```

### Run via Standard Go Test Runner
```powershell
go test -v -count=1 ./benchmarks
```

---

## Comparison Tool (`compare`)

To verify whether a code change improved or regressed Felix, compare the current run against the baseline:

```powershell
go run ./benchmarks --compare benchmarks/results/baseline.json benchmarks/results/latest.json
```
Or:
```powershell
.\benchmarks\scripts\run-benchmark.ps1 -Compare benchmarks/results/baseline.json benchmarks/results/latest.json
```

### Sample Output:
```text
===================================================================
FELIX BENCHMARK COMPARISON
Previous: baseline.json (4b02d3c) | Current: latest.json (4b02d3c)
===================================================================
Metric             Previous     Current      Delta           Assessment
-------------------------------------------------------------------
Requests           126          126          0 (0.0%)        OK
Duration           23.603s      15.148s      -8.455s (-35.8%)OK
Assets             42           42           0               OK
Endpoints          67           67           0               OK
Findings           52           52           0               OK
Verified           19           19           0               OK
Risk Score         160          160          0               OK
False Positives    0            0            0               OK
False Negatives    0            0            0               OK
Status             PASS         PASS         —               PASS
-------------------------------------------------------------------
Benchmark Comparison Outcome: PASS
===================================================================
```

---

## Regression Classification

The benchmark suite classifies execution outcomes into three states:

### 1. `PASS`
- All hard security assertions satisfied.
- False positive corpus yields 0 false findings.
- False negative corpus yields 0 missed detections.
- Safety controls strictly upheld.
- All behavioral metrics within defined bounds.

### 2. `WARNING`
- All hard security assertions and safety controls passed.
- Operational metrics exceeded expected bounds (e.g. request count grew by >50%, or duration exceeded threshold due to environmental latency).
- Requires analyst review to ensure scan efficiency, but does not block certification.

### 3. `REGRESSION`
- A hard security assertion failed (e.g., exposed fixture missed, protected resource flagged as exposed, or verification state altered).
- New false positives or false negatives detected on the benchmark corpus.
- Request explosion detected (>100% request growth).
- Safety control violated (e.g., attempted service-role transmission or destructive HTTP verb).

---

## Security Certification Gate Criteria

A build of Felix is officially certified only when:

1. **Deterministic Certification**: 100% of hard security assertions pass in `synthetic.go`.
2. **False-Positive Corpus**: Zero false positives detected across `false_positives.js` and live targets.
3. **False-Negative Corpus**: Zero true positives missed across `true_positives.js`.
4. **Safety Verification**: Zero destructive requests, zero transmission of sensitive credentials, strict scope adherence.
5. **Regression Test Suite**: Full repository test suite passes (`go test -count=1 ./...`).
6. **Code Hygiene**: Code passes static analysis without warnings (`go vet ./...` and `go build ./...`).

---

## Privacy & Data Sanitization Invariant

In accordance with defensive security principles:
- **No Private Credentials in Git**: Real tokens, client passwords, or service-role keys are NEVER stored in repository fixtures or results.
- **No Raw HTML Dumps**: Raw target response bodies and full HTML dumps are prohibited from Git storage.
- **Sanitized Summaries**: `benchmarks/results/` records only aggregated counts, duration, request statistics, risk scores, and sanitized assertion IDs.
