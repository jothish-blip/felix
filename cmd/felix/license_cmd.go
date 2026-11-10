package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/commercial"
)

func runLicense(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printLicenseHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "install":
		return runLicenseInstall(subArgs)
	case "status":
		return runLicenseStatus(subArgs)
	case "export-usage":
		return runLicenseExportUsage(subArgs)
	case "verify-export":
		return runLicenseVerifyExport(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown license subcommand: %s\n\n", sub)
		printLicenseHelp()
		return clierror.ExitOperational
	}
}

func printLicenseHelp() {
	fmt.Println("Usage: felix license <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  install <path>            Install and activate an enterprise license file (.felixlic or .json)")
	fmt.Println("  status                    Display active license status, entitlements, quotas and concurrency")
	fmt.Println("  export-usage [--out <f>]  Export cryptographically signed air-gapped usage records for billing reconciliation")
	fmt.Println("  verify-export <path>      Verify an air-gapped signed usage export package against trusted keys")
	fmt.Println("\nExamples:")
	fmt.Println("  felix license install license.felixlic")
	fmt.Println("  felix license status")
	fmt.Println("  felix license export-usage --out usage_export.json")
	fmt.Println("  felix license verify-export usage_export.json")
}

func runLicenseInstall(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Missing required license file path")
		fmt.Fprintln(os.Stderr, "Usage: felix license install <license-file>")
		return clierror.ExitOperational
	}

	filePath := args[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read license file: %v\n", err)
		return clierror.ExitOperational
	}

	var signedLic commercial.SignedLicense
	if err := json.Unmarshal(data, &signedLic); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Malformed license file format: %v\n", err)
		return clierror.ExitOperational
	}

	mgr := commercial.GetGlobalLicenseManager()
	res, err := mgr.InstallLicense(&signedLic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] License validation and installation failed: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Println("[+] Enterprise license installed and activated successfully!")
	fmt.Printf("    License ID:      %s\n", res.LicenseID)
	fmt.Printf("    Organization:    %s\n", res.OrganizationID)
	fmt.Printf("    License Tier:    %s\n", res.Tier)
	fmt.Printf("    Issuer Key ID:   %s\n", res.IssuerKeyID)
	fmt.Printf("    Expires At:      %s (%d days remaining)\n", res.ExpiresAt.Format(time.RFC3339), res.DaysRemaining)
	fmt.Printf("    Air-Gapped:      %t\n", res.IsAirGapped)
	return clierror.ExitSuccess
}

func runLicenseStatus(args []string) int {
	jsonOutput := false
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
		}
	}

	mgr := commercial.GetGlobalLicenseManager()
	report, err := mgr.GetQuotaReport()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed retrieving license status: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return clierror.ExitSuccess
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PARAMETER\tVALUE")
	fmt.Fprintln(w, "---------\t-----")
	fmt.Fprintf(w, "License ID\t%s\n", report.LicenseID)
	fmt.Fprintf(w, "Organization\t%s\n", report.OrganizationName)
	fmt.Fprintf(w, "Tier\t%s\n", report.Tier)
	fmt.Fprintf(w, "Deployment Mode\t%s\n", report.DeploymentType)
	fmt.Fprintf(w, "Air-Gapped\t%t\n", report.IsAirGapped)

	if report.MaxAssessments == -1 {
		fmt.Fprintf(w, "Assessments Quota\tUnlimited\n")
	} else {
		fmt.Fprintf(w, "Assessments Quota\t%d\n", report.MaxAssessments)
	}
	fmt.Fprintf(w, "Consumed Assessments\t%d\n", report.ConsumedAssessments)
	fmt.Fprintf(w, "In-Flight Reserved\t%d\n", report.ReservedAssessments)
	if report.RemainingAssessments == -1 {
		fmt.Fprintf(w, "Remaining Balance\tUnlimited\n")
	} else {
		fmt.Fprintf(w, "Remaining Balance\t%d\n", report.RemainingAssessments)
	}

	fmt.Fprintf(w, "Active Concurrency\t%d / %d\n", report.ActiveConcurrency, report.MaxConcurrency)
	if report.ExpiresAt.IsZero() {
		fmt.Fprintf(w, "Expiration\tNever (Perpetual)\n")
	} else {
		status := "Active"
		if report.IsExpired {
			status = "EXPIRED"
		}
		fmt.Fprintf(w, "Expiration\t%s (%d days left, %s)\n", report.ExpiresAt.Format(time.RFC3339), report.DaysUntilExpiry, status)
	}

	_ = w.Flush()
	return clierror.ExitSuccess
}

func runLicenseExportUsage(args []string) int {
	outPath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" && i+1 < len(args) {
			outPath = args[i+1]
			i++
		}
	}

	mgr := commercial.GetGlobalLicenseManager()
	export, err := mgr.ExportSignedUsage(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed generating signed usage export: %v\n", err)
		return clierror.ExitOperational
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed formatting usage export JSON: %v\n", err)
		return clierror.ExitOperational
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed writing export to %s: %v\n", outPath, err)
			return clierror.ExitOperational
		}
		fmt.Printf("[+] Signed usage export saved to: %s\n", outPath)
		fmt.Printf("    Export ID:      %s\n", export.ExportID)
		fmt.Printf("    Records:        %d\n", export.TotalRecords)
		fmt.Printf("    Total Consumed: %d\n", export.TotalQuantityConsumed)
		fmt.Printf("    Digest:         %s\n", export.FinalHashChainDigest)
		fmt.Printf("    Signer Key ID:  %s\n", export.SignerKeyID)
	} else {
		fmt.Println(string(data))
	}

	return clierror.ExitSuccess
}

func runLicenseVerifyExport(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Missing required export package path")
		fmt.Fprintln(os.Stderr, "Usage: felix license verify-export <export-file>")
		return clierror.ExitOperational
	}

	filePath := args[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed reading export file: %v\n", err)
		return clierror.ExitOperational
	}

	var export commercial.SignedUsageExport
	if err := json.Unmarshal(data, &export); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Malformed export JSON format: %v\n", err)
		return clierror.ExitOperational
	}

	mgr := commercial.GetGlobalLicenseManager()
	res, err := commercial.VerifyUsageExport(&export, mgr.KeyRegistry())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Export verification check failed: %v\n", err)
		return clierror.ExitOperational
	}

	if !res.Verified {
		fmt.Fprintf(os.Stderr, "[-] FAILED: Export package failed cryptographic integrity verification!\n")
		for _, issue := range res.Issues {
			fmt.Fprintf(os.Stderr, "    - %s\n", issue)
		}
		return clierror.ExitOperational
	}

	fmt.Println("[+] Cryptographic export verification succeeded!")
	fmt.Printf("    Export ID:        %s\n", res.ExportID)
	fmt.Printf("    License ID:       %s\n", res.LicenseID)
	fmt.Printf("    Total Records:    %d\n", res.TotalRecords)
	fmt.Printf("    Quantity Audited: %d\n", res.TotalQuantityConsumed)
	fmt.Printf("    Hash Continuous:  %t\n", res.ChainContinuous)
	fmt.Printf("    Package Sig OK:   %t\n", res.ExportSignatureValid)
	fmt.Printf("    Record Sigs OK:   %t\n", res.RecordSignaturesValid)
	return clierror.ExitSuccess
}
