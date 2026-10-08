# Contributing to Felix

Thank you for your interest in contributing to Felix! This guide outlines our engineering standards, development workflow, testing practices, and requirements for proposing new detection capabilities.

---

## 1. Development Principles

All contributions must adhere to the core Felix philosophy:

> **Discovery ≠ Detection ≠ Verification ≠ Vulnerability**

When contributing detection rules, engine improvements, or reporting logic:
1. **Never conflate discovery with vulnerability.** Finding a string or an endpoint does not imply a security defect.
2. **Always model negative evidence.** If a server returns `401`, `403`, or `404`, that affirmative negative evidence must be documented and handled.
3. **Strictly non-destructive.** Never introduce destructive HTTP verbs (`POST`/`PUT`/`DELETE` state mutations), database writes, or exploit payloads.
4. **Mandatory Secret Redaction.** Discovered sensitive credentials must be masked before leaving the detection layer.
5. **No Universal False-Positive Claims.** New features must be backed by empirical test fixtures.

---

## 2. Prerequisites & Setup

- **Go:** Version 1.22 or newer.
- **Git:** Version 2.30 or newer.
- **Operating System:** Windows, Linux, or macOS.

### Clone and Build
```bash
git clone https://github.com/jothish-blip/felix.git
cd felix

# Verify compilation
go build ./...

# Build local binary
go build -o bin/felix ./cmd/felix
```

---

## 3. Testing & Verification Standards

Before submitting a pull request, all test suites and static analysis checks must pass cleanly:

```bash
# Run all unit, integration, and CLI tests without caching
go test -count=1 ./...

# Run static analysis
go vet ./...

# Ensure the CLI builds cleanly
go build ./cmd/felix
```

### Development Pipeline
```text
Implement Logic
      ↓
Unit & Integration Tests
      ↓
Add Regression Corpus Fixture
      ↓
Evidence & Verification Validation
      ↓
Documentation Updates
```

---

## 4. Adding New Detection Logic

When proposing new security detection rules, contributors must answer seven questions in their pull request:

1. **What is discovered?** What asset, string, header, or route is initially observed?
2. **What is detected?** What signature, regular expression, or heuristic triggers candidate status?
3. **How does verification work?** What non-destructive, read-only check proves whether an exposure exists?
4. **What evidence is recorded?** What HTTP status, headers, location, or response snippets are captured?
5. **What negative evidence is possible?** What response codes (e.g. 401, 403, 404) prove that the resource is defended?
6. **Why is the assigned severity appropriate?** How does the finding impact confidentiality, integrity, or availability?
7. **What false positives were considered?** What development frameworks, chunk hashes, or benign strings were tested?

---

## 5. Subsystem Contribution Guidelines

### Adding Secret Signatures (`pkg/secrets`)
1. Add the regular expression pattern to `pkg/secrets/patterns.go`.
2. Ensure prefix boundaries are strictly defined to prevent matching arbitrary variable names.
3. Add false-positive test cases in `pkg/secrets/filters.go` (e.g., test placeholders, UUIDs, git hashes).
4. Verify values are redacted using `RedactSecret()` in `pkg/secrets/finding.go`.
5. Add corresponding unit tests in `pkg/secrets/detector_test.go`.

### Adding Cloud & BaaS Checks (`pkg/cloud`)
1. Implement the provider detector in `pkg/cloud/`.
2. Use `pkg/cloud/client.go` to ensure bounded timeouts and response size limits.
3. Probes must be read-only HTTP GET or HEAD requests.
4. Record affirmative negative evidence on HTTP `401 Unauthorized` or `403 Forbidden` (`VerificationNotExposed`).
5. Add unit and mock HTTP server tests in `pkg/cloud/cloud_test.go`.

### Adding API Security Audits (`pkg/api`)
1. Implement endpoint extraction or header analysis in `pkg/api/`.
2. Classify endpoint taxonomy accurately (`pkg/api/endpoints.go`).
3. Handle redirect responses (`301`, `302`, `308`) gracefully as non-exposed redirects.
4. Add corresponding test cases in `pkg/api/api_test.go`.

### Adding Regression Tests (`test/regression_test.go`)
Whenever fixing a false positive or false negative:
1. Add a test fixture under `testdata/regression/`.
2. Add a test case to `test/regression_test.go` or `test/cli_test.go`.
3. Assert both the positive detection (true positive) and the negative rejection (false positive suppression).

---

## 6. Code Style & Architecture Conventions

- **Standard Library First:** Favor the Go standard library (`net/http`, `crypto/tls`, `encoding/json`, `flag`, `sync`). Avoid heavy external dependencies.
- **Zero Exposure of Internal Engine Terminology:** Never expose internal numbers (`Engine 1` through `Engine 5`) to CLI terminal output or HTML reports. Use user-facing terminology: *Asset Discovery*, *Secret Intelligence*, *Cloud & BaaS*, *API Security*, *Risk Assessment*.
- **Thread Safety:** Protect concurrent data structures using `sync.Mutex` or channels. Ensure worker pool semaphores are always released via `defer`.
- **Context Propagation:** Always propagate `context.Context` to network calls and respect context cancellation (`ctx.Done()`).

---

## 7. Pull Request Process

1. **Fork and Branch:** Create a feature branch off `main` (`git checkout -b feature/my-improvement`).
2. **Implement and Test:** Write your code, update tests, and verify `go test -count=1 ./...` and `go vet ./...`.
3. **Commit Messages:** Follow concise conventional commit style (e.g. `feat: add SendGrid API key detection`, `fix: suppress Next.js build chunk entropy false positives`).
4. **Submit PR:** Clearly describe the motivation, evidence model, and test verification in your pull request description.

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview and quick start.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design, pipeline, and concurrency.
- **[Operator Usage Guide](USAGE.md)** — CLI commands, options, and exit codes.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Evidence and verification states.
- **[Security & Safety Controls](SECURITY.md)** — Safety boundaries and non-destructive guarantees.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Boundaries of black-box scanning.
