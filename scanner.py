import json
import boto3
import urllib.parse
import os
import yara

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get('DYNAMODB_TABLE', 'sentinel-threat-log')

# Enterprise YARA Engine Ruleset
YARA_RULES = """
rule Catch_EICAR_And_Suspicious_Hex {
    meta:
        description = "Detects EICAR and generic suspicious hex patterns"
        author = "Project Sentinel CNAPP"
        threat_level = "High"
    strings:
        # Text-based signature
        $eicar_string = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        # Hexadecimal pattern matching (simulating a packed executable signature)
        $hex_pattern = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 }
    condition:
        $eicar_string or $hex_pattern
}
"""

def lambda_handler(event, context):
    print("Event Received:", json.dumps(event))
    
    # 1. Parse the S3 Event
    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])
    except KeyError:
        return {"statusCode": 400, "body": "Invalid event structure"}

    # 2. Intercept and Download File to Memory
    print(f"Scanning target: s3://{bucket}/{key}")
    response = s3_client.get_object(Bucket=bucket, Key=key)
    file_content = response['Body'].read()

    # 3. Compile and Execute YARA Engine
    rules = yara.compile(source=YARA_RULES)
    matches = rules.match(data=file_content)

    # 4. Quarantine Protocol
    if matches:
        matched_rule = matches[0].rule
        print(f"🚨 THREAT DETECTED: [{matched_rule}] in {key}! Initiating Quarantine.")
        
        # Tag as malicious in S3
        s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={'TagSet': [{'Key': 'SecurityStatus', 'Value': 'QUARANTINED'}, {'Key': 'ThreatType', 'Value': matched_rule}]}
        )
        
        # Log to Sentinel Registry (DynamoDB)
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                'tenant_id': bucket,
                'threat_id': f"{bucket}::{key}",
                'status': 'QUARANTINED',
                'file_key': key,
                'yara_match': matched_rule,
                'resolution': 'PENDING_ADMIN_REVIEW'
            }
        )
        return {"statusCode": 200, "body": f"Quarantined by YARA rule: {matched_rule}"}
        
    else:
        print(f"✅ {key} is clean.")
        s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={'TagSet': [{'Key': 'SecurityStatus', 'Value': 'CLEAN'}]}
        )
        return {"statusCode": 200, "body": "File Clean"}