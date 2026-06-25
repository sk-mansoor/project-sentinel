import os
import glob
import csv
import boto3
from datetime import datetime

def sync_to_dynamodb():
    print("Initiating Sentinel Data Bridge...")
    
    # 1. Find the latest Prowler CSV report recursively
    csv_files = glob.glob('**/*.csv', recursive=True)
    if not csv_files:
        print("Error: No Prowler CSV found anywhere in the workspace!")
        return

    latest_csv = max(csv_files, key=os.path.getctime)
    print(f"Parsing report discovered at: {latest_csv}")

    # 2. Calculate the Compliance Score (Bulletproof Parsing)
    passed = 0
    failed = 0

    # utf-8-sig removes invisible Byte Order Marks (BOM) from Prowler's output
    with open(latest_csv, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Force all CSV headers and values to uppercase to guarantee a match
            row_data = {str(k).strip().upper(): str(v).strip().upper() for k, v in row.items()}
            status = row_data.get('STATUS', '')
            
            if status == 'PASS':
                passed += 1
            elif status == 'FAIL':
                failed += 1

    total = passed + failed
    score = int((passed / total) * 100) if total > 0 else 0
    print(f"Calculated Score: {score}% ({passed} Passed, {failed} Failed)")

    if total == 0:
        print("Warning: Could not parse PASS/FAIL columns correctly. Check CSV structure.")

    # 3. Push to DynamoDB (Locked to us-east-1 and your exact table name)
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('sentinel-compliance-history')
    
    try:
        table.put_item(
            Item={
                'TenantID': 'admin',
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