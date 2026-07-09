
import os
import glob
import csv
import sys
import boto3
from datetime import datetime
 
# ─────────────────────────────────────────────────────────────────────────────
# Config from environment
# ─────────────────────────────────────────────────────────────────────────────
REGION          = os.environ.get('DYNAMODB_REGION', 'us-east-1')
TABLE_NAME      = os.environ.get('COMPLIANCE_TABLE', 'sentinel-compliance-history')
TENANT_ID       = os.environ.get('TENANT_ID', 'admin')
SEARCH_ROOT     = os.environ.get('PROWLER_OUTPUT_DIR', '.')
 
# Subdirectory names that should never be treated as the main Prowler report
EXCLUDE_DIRS = {'compliance', 'benchmark', 'summary', 'temp', 'archive'}
 
 
def _find_latest_prowler_csv(search_root: str) -> str | None:
    """
    Recursively finds the most recently *modified* CSV that looks like a
    Prowler main report (not a compliance-summary subfolder output).
 
    M10 fix: uses getmtime (last file modification) instead of getctime
    (inode metadata change on Linux, which is not creation time).
    M10 fix: path exclusion is checked per path component, not via a single
    substring match that could accidentally exclude valid files.
    """
    all_csvs = glob.glob(os.path.join(search_root, '**', '*.csv'), recursive=True)
 
    main_reports = []
    for path in all_csvs:
        # Exclude if ANY part of the path (directory component) is in EXCLUDE_DIRS
        parts = set(os.path.normpath(path).split(os.sep))
        if parts & EXCLUDE_DIRS:
            continue
        main_reports.append(path)
 
    if not main_reports:
        return None
 
    # Sort by last modification time (most recent first)
    return max(main_reports, key=os.path.getmtime)
 
 
def sync_to_dynamodb():
    print("Initiating Sentinel Data Bridge...")
 
    # ── 1. Locate the latest CSV ─────────────────────────────────────────────
    latest_csv = _find_latest_prowler_csv(SEARCH_ROOT)
 
    if not latest_csv:
        print("ERROR: No main Prowler CSV found. Aborting — will not push a fake score.")
        sys.exit(1)
 
    print(f"Parsing: {latest_csv}")
 
    # ── 2. Parse compliance metrics ──────────────────────────────────────────
    passed       = 0
    failed       = 0
    stale_keys   = 0
    missing_mfa  = 0
    parse_error  = False
 
    try:
        with open(latest_csv, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f, delimiter=';')
 
            if not reader.fieldnames:
                raise ValueError("CSV has no headers — likely wrong file or wrong delimiter.")
 
            for row in reader:
                row_data  = {str(k).strip().upper(): str(v).strip().upper() for k, v in row.items()}
                status    = row_data.get('STATUS', '')
                check_id  = row_data.get('CHECK_ID', '')
 
                if status == 'PASS':
                    passed += 1
                elif status == 'FAIL':
                    failed += 1
 
                if status == 'FAIL' and 'IAM' in check_id:
                    if 'ACCESSKEY' in check_id and ('UNUSED' in check_id or 'OLD' in check_id):
                        stale_keys += 1
                    if 'MFA' in check_id:
                        missing_mfa += 1
 
    except Exception as e:
        print(f"CSV PARSE ERROR: {e}")
        parse_error = True
 
    total = passed + failed
 
    # M9 fix: if we could not parse anything meaningful, write an explicit error
    # status instead of silently pushing 0% which looks like a real scan result.
    if parse_error or total == 0:
        print(
            "WARNING: Could not parse PASS/FAIL columns correctly.\n"
            "Writing PARSE_ERROR status to DynamoDB instead of a fake 0% score."
        )
        _push_to_dynamodb(
            score=0,
            passed=0,
            failed=0,
            stale_keys=0,
            missing_mfa=0,
            status='PARSE_ERROR',
        )
        return
 
    score = int((passed / total) * 100)
    print(f"Score: {score}% | Passed: {passed} | Failed: {failed} | "
          f"Stale Keys: {stale_keys} | Missing MFA: {missing_mfa}")
 
    _push_to_dynamodb(score, passed, failed, stale_keys, missing_mfa, status='OK')
 
 
def _push_to_dynamodb(score, passed, failed, stale_keys, missing_mfa, status='OK'):
    """Writes today's compliance record to DynamoDB.
 
    Uses a composite sort key  ScanDate#status  so that an OK run and a
    PARSE_ERROR run on the same day are stored separately and a dashboard
    trend chart can filter out error records.
    """
    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    table    = dynamodb.Table(TABLE_NAME)
 
    scan_date = datetime.now().strftime('%Y-%m-%d')
    sort_key  = f"{scan_date}#{status}"   # e.g. "2025-07-03#OK"
 
    try:
        table.put_item(
            Item={
                'TenantID':        TENANT_ID,
                'ScanDate':        sort_key,         # sort key — includes status
                'ScanDatePlain':   scan_date,         # plain date for queries
                'ComplianceScore': score,
                'PassedChecks':    passed,
                'FailedChecks':    failed,
                'StaleKeys':       stale_keys,
                'MissingMFA':      missing_mfa,
                'ParseStatus':     status,
            }
        )
        print(f"✅ Synced to DynamoDB — TenantID: {TENANT_ID}, Date: {sort_key}, Score: {score}%")
    except Exception as e:
        print(f"DATABASE ERROR: {e}")
        sys.exit(1)
 
 
if __name__ == "__main__":
    sync_to_dynamodb()
