package main

import (
	"fmt"
	"os"
)

func main() {
	cfg := RunnerConfig{}

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--help", "-h":
			printHelp()
			os.Exit(0)
		case "--synthetic-only", "--deterministic-only":
			cfg.SyntheticOnly = true
		case "--live-only":
			cfg.LiveOnly = true
		case "--baseline":
			cfg.BaselineSave = true
		case "--quiet", "-q":
			cfg.Quiet = true
		case "--verbose", "-v":
			cfg.Verbose = true
		case "--out", "-o":
			if i+1 < len(args) {
				i++
				cfg.OutPath = args[i]
			}
		case "--compare":
			if i+2 < len(args) {
				cfg.ComparePrev = args[i+1]
				cfg.CompareCurr = args[i+2]
				i += 2
			} else {
				fmt.Fprintf(os.Stderr, "[-] Error: --compare requires two file paths: <prev.json> <curr.json>\n")
				os.Exit(2)
			}
		default:
			// If two bare file paths are given, treat as comparison
			if len(args) == 2 && !cfg.SyntheticOnly && !cfg.LiveOnly {
				cfg.ComparePrev = args[0]
				cfg.CompareCurr = args[1]
				break
			}
			fmt.Fprintf(os.Stderr, "[-] Unknown option: %s\n", arg)
			printHelp()
			os.Exit(2)
		}
	}

	_, code := RunBenchmarkSuite(cfg)
	os.Exit(code)
}

func printHelp() {
	fmt.Println(`Felix Benchmark & Certification Suite

Usage:
  go run ./benchmarks [options]

Commands & Options:
  --synthetic-only       Execute deterministic synthetic certification suite only
  --live-only            Execute live targets benchmark only
  --baseline             Save benchmark run as the reference baseline (baseline.json)
  --compare <prev> <curr> Compare two benchmark JSON result files
  --out <file>           Output file path for machine-readable JSON [default: latest.json]
  --quiet, -q            Suppress progress logs
  --verbose, -v          Show detailed assertion and debug output
  --help, -h             Show this help message

Examples:
  go run ./benchmarks
  go run ./benchmarks --synthetic-only
  go run ./benchmarks --baseline
  go run ./benchmarks --compare benchmarks/results/baseline.json benchmarks/results/latest.json`)
}
