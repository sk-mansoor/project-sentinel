import boto3
import json
import os

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    print(f"Event detected: {json.dumps(event)}")
    
    # Parse the EventBridge CloudTrail event
    detail = event.get('detail', {})
    event_name = detail.get('eventName')
    bucket_name = detail.get('requestParameters', {}).get('bucketName')
    user_identity_arn = detail.get('userIdentity', {}).get('arn', '')
    
    # ==========================================
    # 1. STATE BREAKER (CIRCUIT BREAKER)
    # ==========================================
    if "sentinel-remediator" in user_identity_arn:
        print("Circuit Breaker: Ignoring self-triggered remediation event.")
        return {"status": "ignored", "reason": "Self-triggered event"}
        
    if not bucket_name:
        return {"status": "ignored", "reason": "No bucket name"}

    # ==========================================
    # 2. GLOBAL WHITELIST CHECK
    # ==========================================
    is_whitelisted = False
    try:
        tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
        for tag in tags.get('TagSet', []):
            if tag['Key'] == 'Sentinel-Override' and tag['Value'] == 'Approved':
                is_whitelisted = True
                break
    except Exception:
        pass # No tags exist

    # ==========================================
    # 3. TRIGGER 1 & EXCEPTION WORKFLOW: Public Access Block
    # ==========================================
    is_vulnerable = False
    is_securing = False
    
    # Catch CLI "Delete" commands
    if event_name in ["DeletePublicAccessBlock", "DeleteBucketPublicAccessBlock"]:
        is_vulnerable = True
        
    # Catch Console UI "Uncheck/Check" commands
    elif event_name in ["PutPublicAccessBlock", "PutBucketPublicAccessBlock"]:
        try:
            # Query the LIVE state of the bucket
            posture = s3_client.get_public_access_block(Bucket=bucket_name)
            config = posture.get('PublicAccessBlockConfiguration', {})
            
            # If ALL 4 strict settings are TRUE, the Admin is securing the bucket!
            if (str(config.get('BlockPublicAcls')).lower() == 'true' and \
                str(config.get('IgnorePublicAcls')).lower() == 'true' and \
                str(config.get('BlockPublicPolicy')).lower() == 'true' and \
                str(config.get('RestrictPublicBuckets')).lower() == 'true'):
                is_securing = True
            else:
                is_vulnerable = True
        except Exception as e:
            print(f"Posture Check Error: {e}")
            is_vulnerable = True

    # --- ACTION: THE ADMIN SECURED THE BUCKET ---
    if is_securing:
        print(f"✅ {bucket_name} was manually secured. Checking for whitelist tags...")
        if is_whitelisted:
            try:
                # Safely remove ONLY the Sentinel-Override tag, keeping other tags intact
                tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
                new_tags = [t for t in tagging.get('TagSet', []) if t['Key'] != 'Sentinel-Override']
                
                if new_tags:
                    s3_client.put_bucket_tagging(Bucket=bucket_name, Tagging={'TagSet': new_tags})
                else:
                    s3_client.delete_bucket_tagging(Bucket=bucket_name)
                print("Whitelist revoked. Engine is fully re-armed and monitoring.")
            except Exception as e:
                print(f"❌ Failed to remove tag: {str(e)} - Check IAM Permissions!")
                
        return {"status": "re-armed", "bucket": bucket_name}

    # --- ACTION: THE BUCKET IS VULNERABLE ---
    if is_vulnerable:
        if is_whitelisted:
            print(f"Whitelist tag detected on {bucket_name}. Allowing public access.")
            return {"status": "whitelisted", "reason": "Admin approved exception"}
            
        print(f"🚨 ALERT: Public Access Block compromised on {bucket_name}! Auto-remediating...")
        
        # Action A: Instantly secure the bucket again
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Action B: Send the Incident Email with the Dashboard Link
        sns_arn = os.environ.get('SNS_TOPIC_ARN')
        override_url = f"http://localhost:8501/?action=override&bucket={bucket_name}"
        
        message = (
            f"🚨 SENTINEL AUTO-REMEDIATION TRIGGERED 🚨\n\n"
            f"Target: S3 Bucket '{bucket_name}'\n"
            f"Incident: The strict Public Access Block was removed or weakened via the AWS Console/CLI.\n\n"
            f"Action Taken: Project Sentinel intercepted the action and instantly locked the bucket back to secure conditions.\n\n"
            f"ADMIN REVIEW REQUIRED:\n"
            f"If this was intentional and you require this bucket to be public, click the secure link below:\n\n"
            f"👉 {override_url}\n"
        )
        
        try:
            sns_client.publish(
                TopicArn=sns_arn,
                Subject="🚨 Sentinel Alert: Bucket Auto-Secured (Review Required)",
                Message=message
            )
            print("SNS Email dispatched successfully.")
        except Exception as e:
            print(f"Failed to send SNS Email: {str(e)}")
        
        return {"status": "remediated", "bucket": bucket_name, "action": "Public Access Block Re-applied"}

    # ==========================================
    # 4. TRIGGER 2: Someone suspended Versioning (Ransomware risk)
    # ==========================================
    elif event_name == "PutBucketVersioning":
        versioning_status = detail.get('requestParameters', {}).get('VersioningConfiguration', {}).get('Status')
        
        if versioning_status == "Suspended":
            if is_whitelisted:
                print(f"Whitelist tag detected. Allowing versioning to be suspended.")
                return {"status": "whitelisted"}
                
            print(f"🚨 ALERT: Versioning suspended on {bucket_name}! Auto-remediating...")
            
            s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            sns_arn = os.environ.get('SNS_TOPIC_ARN')
            message = (
                f"🚨 SENTINEL AUTO-REMEDIATION TRIGGERED 🚨\n\n"
                f"Target: S3 Bucket '{bucket_name}'\n"
                f"Incident: Bucket Versioning was suspended (High risk for Ransomware data loss).\n\n"
                f"Action Taken: Project Sentinel instantly re-enabled Versioning.\n\n"
                f"ADMIN REVIEW REQUIRED:\n"
                f"Do you actually need versioning turned off? If this was intentional to save storage costs, please formally submit an architecture exception."
            )
            
            sns_client.publish(
                TopicArn=sns_arn,
                Subject="🚨 Sentinel Alert: Versioning Auto-Restored",
                Message=message
            )
            return {"status": "remediated", "bucket": bucket_name, "action": "Versioning Re-enabled"}
            
    return {"status": "ignored", "reason": "Not a targeted security event"}