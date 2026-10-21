package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"felix/pkg/ci"
	"felix/pkg/clierror"
)

// runCI executes the "felix ci" subcommand optimized for continuous integration pipelines.
func runCI(args []string) int {
	if len(args) == 0 {
		printCIHelp()
		return clierror.ExitSuccess
	}

	subCmd := args[0]
	if subCmd == "--help" || subCmd == "-h" || subCmd == "help" {
		printCIHelp()
		return clierror.ExitSuccess
	}

	subArgs := args
	if subCmd == "run" || subCmd == "scan" {
		subArgs = args[1:]
	}

	var (
		targetURL       string
		assessmentRef   string
		policyPath      string
		baselineRef     string
		baselineScope   string
		outputDir       string
		sarifFile       string = "felix.sarif"
		jsonFile        string = "felix.json"
		htmlFile        string = "felix.html"
		timeoutStr      string = "30s"
		quiet           bool
		verbose         bool
		summaryPath     string
		outputPath      string
		verifyBinPath   string
		expectedVersion       string
		expectedSHA256        string
		requireSHA256         bool
		allowLoopback         bool
		allowPrivate          bool
		prComment             bool
		prInline              bool
		prNumber              int
		githubToken           string
		githubRepo            string
		commitSHA             string
		feedbackFailurePolicy string = "warn"
		commentTag            string
		githubAPIBaseURL      string
	)

	for i := 0; i < len(subArgs); i++ {
		arg := subArgs[i]
		switch arg {
		case "--target", "-t":
			if i+1 < len(subArgs) {
				targetURL = subArgs[i+1]
				i++
			}
		case "--assessment", "--asm", "--ref":
			if i+1 < len(subArgs) {
				assessmentRef = subArgs[i+1]
				i++
			}
		case "--policy", "-p":
			if i+1 < len(subArgs) {
				policyPath = subArgs[i+1]
				i++
			}
		case "--baseline", "-b":
			if i+1 < len(subArgs) {
				baselineRef = subArgs[i+1]
				i++
			}
		case "--baseline-scope", "--scope":
			if i+1 < len(subArgs) {
				baselineScope = strings.ToLower(subArgs[i+1])
				i++
			}
		case "--output-dir", "-o":
			if i+1 < len(subArgs) {
				outputDir = subArgs[i+1]
				i++
			}
		case "--sarif":
			if i+1 < len(subArgs) && !strings.HasPrefix(subArgs[i+1], "-") {
				sarifFile = subArgs[i+1]
				i++
			}
		case "--json":
			if i+1 < len(subArgs) && !strings.HasPrefix(subArgs[i+1], "-") {
				jsonFile = subArgs[i+1]
				i++
			}
		case "--html":
			if i+1 < len(subArgs) && !strings.HasPrefix(subArgs[i+1], "-") {
				htmlFile = subArgs[i+1]
				i++
			}
		case "--timeout":
			if i+1 < len(subArgs) {
				timeoutStr = subArgs[i+1]
				i++
			}
		case "--summary-path":
			if i+1 < len(subArgs) {
				summaryPath = subArgs[i+1]
				i++
			}
		case "--output-path":
			if i+1 < len(subArgs) {
				outputPath = subArgs[i+1]
				i++
			}
		case "--verify-bin":
			if i+1 < len(subArgs) {
				verifyBinPath = subArgs[i+1]
				i++
			}
		case "--expected-version":
			if i+1 < len(subArgs) {
				expectedVersion = subArgs[i+1]
				i++
			}
		case "--expected-sha256":
			if i+1 < len(subArgs) {
				expectedSHA256 = subArgs[i+1]
				i++
			}
		case "--require-sha256", "--require-checksum":
			requireSHA256 = true
		case "--allow-loopback":
			allowLoopback = true
		case "--allow-private":
			allowPrivate = true
		case "--pr-comment":
			prComment = true
		case "--pr-inline":
			prInline = true
		case "--pr-number":
			if i+1 < len(subArgs) {
				if n, err := strconv.Atoi(subArgs[i+1]); err == nil {
					prNumber = n
				}
				i++
			}
		case "--github-token":
			if i+1 < len(subArgs) {
				githubToken = subArgs[i+1]
				i++
			}
		case "--repo":
			if i+1 < len(subArgs) {
				githubRepo = subArgs[i+1]
				i++
			}
		case "--commit-sha":
			if i+1 < len(subArgs) {
				commitSHA = subArgs[i+1]
				i++
			}
		case "--feedback-failure-policy":
			if i+1 < len(subArgs) {
				feedbackFailurePolicy = subArgs[i+1]
				i++
			}
		case "--comment-tag":
			if i+1 < len(subArgs) {
				commentTag = subArgs[i+1]
				i++
			}
		case "--github-api-url":
			if i+1 < len(subArgs) {
				githubAPIBaseURL = subArgs[i+1]
				i++
			}
		case "--quiet", "-q":
			quiet = true
		case "--verbose", "-v":
			verbose = true
		case "--help", "-h":
			printCIHelp()
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && targetURL == "" && assessmentRef == "" {
				if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
					targetURL = arg
				} else {
					assessmentRef = arg
				}
			}
		}
	}

	// Standalone binary verification sub-operation
	if verifyBinPath != "" {
		if err := ci.VerifyBinaryWithIntegrity(verifyBinPath, expectedVersion, expectedSHA256, requireSHA256); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Binary verification failed: %v\n", err)
			return clierror.ExitOperational
		}
		if !quiet {
			fmt.Printf("[✓] Binary verification succeeded for: %s\n", verifyBinPath)
		}
		return clierror.ExitSuccess
	}

	cfg := &ci.Config{
		Provider:              ci.DetectProvider(),
		TargetURL:             targetURL,
		AssessmentRef:         assessmentRef,
		PolicyPath:            policyPath,
		BaselineRef:           baselineRef,
		BaselineScope:         baselineScope,
		OutputDir:             outputDir,
		SARIFFile:             sarifFile,
		JSONFile:              jsonFile,
		HTMLFile:              htmlFile,
		Timeout:               timeoutStr,
		Quiet:                 quiet,
		Verbose:               verbose,
		SummaryPath:           summaryPath,
		OutputPath:            outputPath,
		ExpectedVersion:       expectedVersion,
		ExpectedSHA256:        expectedSHA256,
		RequireSHA256:         requireSHA256,
		AllowLoopback:         allowLoopback,
		AllowPrivateIPs:       allowPrivate,
		PRComment:             prComment,
		PRInline:              prInline,
		PRNumber:              prNumber,
		GitHubToken:           githubToken,
		GitHubRepo:            githubRepo,
		CommitSHA:             commitSHA,
		FeedbackFailurePolicy: feedbackFailurePolicy,
		CommentTag:            commentTag,
		GitHubAPIBaseURL:      githubAPIBaseURL,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	res, _ := ci.Run(ctx, cfg, nil)
	if !quiet && res != nil {
		fmt.Println(res.DiagnosticSummary)
	}

	if res != nil {
		return res.ExitCode
	}
	return clierror.ExitOperational
}

func printCIHelp() {
	fmt.Print(banner)
	fmt.Println("Usage:")
	fmt.Println("  felix ci run [options] (--target <url> | --assessment <ref>)")
	fmt.Println("  felix ci --verify-bin <path> [--expected-version <v>] [--expected-sha256 <hash>]")
	fmt.Println("\nExecute continuous-integration automated security assessments with deterministic exit codes.")
	fmt.Println("\nOptions:")
	fmt.Println("  --target, -t <url>               Authorized target URL to assess")
	fmt.Println("  --assessment, --ref <id>         Target project assessment ID or Ref in database")
	fmt.Println("  --policy, -p <file>              Path to threshold policy YAML/JSON file for build gating")
	fmt.Println("  --baseline, -b <id>              Baseline execution or snapshot ID for finding delta comparison")
	fmt.Println("  --baseline-scope <scope>         Baseline policy scope: all (default), new, new_and_regressed")
	fmt.Println("  --output-dir, -o <dir>           Directory where reports will be saved [default: felix-reports]")
	fmt.Println("  --sarif [file]                   Name/path of generated SARIF 2.1.0 report [default: felix.sarif]")
	fmt.Println("  --json [file]                    Name/path of generated JSON report [default: felix.json]")
	fmt.Println("  --html [file]                    Name/path of generated HTML report [default: felix.html]")
	fmt.Println("  --timeout <duration>             Per-request HTTP timeout [default: 30s]")
	fmt.Println("  --summary-path <file>            Destination path for markdown step summary ($GITHUB_STEP_SUMMARY)")
	fmt.Println("  --output-path <file>             Destination path for step outputs ($GITHUB_OUTPUT)")
	fmt.Println("  --verify-bin <path>              Verify executable file existence, magic bytes, and version probe")
	fmt.Println("  --expected-version <v>           Expected version string for binary verification")
	fmt.Println("  --expected-sha256 <hash>         Expected SHA256 hexadecimal digest for binary verification")
	fmt.Println("  --require-sha256                 Enforce cryptographic integrity (fails closed if checksum is missing)")
	fmt.Println("  --allow-loopback                 Allow scan targets on loopback addresses (127.0.0.0/8, ::1)")
	fmt.Println("  --allow-private                  Allow scan targets on RFC 1918 private IP subnets")
	fmt.Println("  --pr-comment                     Publish or update Pull Request summary comment on GitHub")
	fmt.Println("  --pr-inline                      Publish inline code review comments on GitHub for findings with source locations")
	fmt.Println("  --pr-number <n>                  Target pull request number (defaults to auto-detection from CI event)")
	fmt.Println("  --github-token <token>           GitHub token for PR feedback (defaults to GITHUB_TOKEN environment variable)")
	fmt.Println("  --repo <owner/repo>              GitHub repository slug (defaults to GITHUB_REPOSITORY environment variable)")
	fmt.Println("  --commit-sha <sha>               Target commit SHA for inline code review comments (defaults to GITHUB_SHA)")
	fmt.Println("  --feedback-failure-policy <pol>  Failure behavior if PR feedback fails: warn (default) or fail")
	fmt.Println("  --comment-tag <tag>              Stable marker tag for updating existing PR comment idempotently")
	fmt.Println("  --quiet, -q                      Suppress live terminal output")
	fmt.Println("  --verbose, -v                    Enable detailed operational output")
	fmt.Println("\nExit Codes:")
	fmt.Println("  0: Success (No security policy violations established)")
	fmt.Println("  1: Security Failure (Completed assessment violated policy threshold)")
	fmt.Println("  2: Operational Error (Assessment failed, crawl defects, or invalid configuration)")
}
