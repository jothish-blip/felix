# FELIX Pilot Campaign Directory Template (`<campaign_id>`)

Do **not** commit customer credentials, bearer tokens, private keys, signed contracts, or proprietary customer reports into Git-tracked template directories.

For an owner-authorized external engagement, create a working campaign directory outside version control (or under a gitignored campaign workspace path):

`test/evidence/phase10/pilot_campaigns/<campaign_id>/`

## Required Directory Layout

```text
<campaign_id>/
  01_authorization_contract.json      # Owner-signed AuthorizationContract (confirmed: true, UTC window, exclusions)
  02_ground_truth_registry.json       # Independently established GroundTruthRegistry (derived_from_scanner: false)
  02_ground_truth_registry.sha256     # Pre-scan digest output from: felix validate hash-gt
  03_campaign_manifest.json           # Pre-scan CampaignManifest binding authorization + ground_truth_sha256
  04_roles_config.json                # Approved test-only credentials (local mode 0600, never committed)
  05_readiness_report.json            # Output of: felix validate pilot-readiness
  06_blind_output/                    # Blind assessment output (0700 dir; assessment_report.json, authorization_summary.json)
  07_accuracy_eval.json               # Pre-retest accuracy output from: felix validate evaluate
  08_retest_expected.json             # Expected remediation verdicts (FIXED / STILL_PRESENT)
  09_retest_output/                   # Live remediation retest output (retest_report.json)
  10_final_accuracy_and_audit.json    # Final post-retest evaluation + redaction & blindness integrity proof
```
