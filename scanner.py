import json
import boto3
import urllib.parse
import os

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get('DYNAMODB_TABLE')

# Threat Intelligence: The standard EICAR test string
MALWARE_SIGNATURE = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

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

    # 3. Engine Analysis (Signature Matching)
    is_malicious = MALWARE_SIGNATURE in file_content

    # 4. Quarantine Action
    if is_malicious:
        print(f"🚨 THREAT DETECTED in {key}! Initiating Quarantine Protocol.")
        
        # Tag as malicious
        s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={'TagSet': [{'Key': 'SecurityStatus', 'Value': 'QUARANTINED'}, {'Key': 'ThreatType', 'Value': 'EICAR_TEST'}]}
        )
        
        # Log to Sentinel Registry (DynamoDB)
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                'tenant_id': bucket,
                'threat_id': f"{bucket}::{key}",
                'status': 'QUARANTINED',
                'file_key': key,
                'resolution': 'PENDING_ADMIN_REVIEW'
            }
        )
        
        return {"statusCode": 200, "body": "Threat Quarantined"}
        
    else:
        print(f"✅ {key} is clean.")
        s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={'TagSet': [{'Key': 'SecurityStatus', 'Value': 'CLEAN'}]}
        )
        return {"statusCode": 200, "body": "File Clean"}