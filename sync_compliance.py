import os
import glob
import csv
import boto3
from datetime import datetime

def sync_to_dynamodb():
    print("Initiating Sentinel Data Bridge...")
    
    # 1. Find the latest Prowler CSV report
    ccsv_files = glob.glob('**/*.csv', recursive=True)
    if not csv_files:
        print("Error: No Prowler CSV found anywhere in the workspace!")
        return

    latest_csv = max(csv_files, key=os.path.getctime)
    print(f"Parsing report discovered at: {latest_csv}")

    # 2. Calculate the Compliance Score
    passed = 0
    failed = 0

    with open(latest_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Prowler v4 uses 'STATUS' or 'Status'
            status = row.get('STATUS', row.get('Status', '')).upper()
            if status == 'PASS':
                passed += 1
            elif status == 'FAIL':
                failed += 1

    total = passed + failed
    score = int((passed / total) * 100) if total > 0 else 0
    print(f"Calculated Score: {score}% ({passed} Passed, {failed} Failed)")

    # 3. Push to DynamoDB
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('sentinel-compliance-history')
    
    try:
        table.put_item(
            Item={
                'TenantID': 'admin',  # Hardcoded to match your Streamlit login
                'ScanDate': datetime.now().strftime('%Y-%m-%d'),
                'ComplianceScore': score,
                'PassedChecks': passed,
                'FailedChecks': failed
            }
        )
        print("Successfully synced daily compliance to DynamoDB!")
    except Exception as e:
        print(f"Database Error: {e}")

if __name__ == "__main__":
    sync_to_dynamodb()