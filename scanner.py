import json
import boto3
import urllib.parse
import os
import yara
from botocore.exceptions import ClientError
 
# ─────────────────────────────────────────────────────────────────────────────
# Config from environment (no hardcoded region or bucket names)
# ─────────────────────────────────────────────────────────────────────────────
SCAN_REGION       = os.environ.get('AWS_SCAN_REGION', 'us-east-1')
TABLE_NAME        = os.environ.get('DYNAMODB_TABLE', 'sentinel-tenant-registry')
QUARANTINE_BUCKET = os.environ.get('QUARANTINE_BUCKET', 'sentinel-quarantine')
MAX_SCAN_BYTES    = int(os.environ.get('MAX_SCAN_SIZE_MB', '50')) * 1024 * 1024
 
# ─────────────────────────────────────────────────────────────────────────────
# AWS clients
# ─────────────────────────────────────────────────────────────────────────────
s3_client = boto3.client('s3')
dynamodb  = boto3.resource('dynamodb')
 
# ─────────────────────────────────────────────────────────────────────────────
# YARA ruleset
#
# Escaping note (correct — do NOT change):
#   Python source has 4 backslashes → 2 literal backslashes at runtime
#   YARA then parses its own string escape: \\ → 1 backslash in the pattern
#   That single backslash matches the real EICAR test file exactly.
#
# The hex pattern {58 35 ... 5C ...} is the first 16 bytes of EICAR re-encoded
# as hex. It overlaps with $eicar_string and adds no separate detection, but
# demonstrates hex matching syntax. A real deployment would add community
# YARA rules here (e.g. https://github.com/Yara-Rules/rules).
# ─────────────────────────────────────────────────────────────────────────────
YARA_RULES = """
rule Catch_EICAR_And_Suspicious_Hex {
    meta:
        description = "Detects EICAR test file via string and hex pattern"
        author      = "Project Sentinel"
        threat_level = "High"
    strings:
        $eicar_string = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $hex_pattern  = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 }
    condition:
        $eicar_string or $hex_pattern
}
"""
 
# ─────────────────────────────────────────────────────────────────────────────
# Compile YARA once at module load (not inside the handler — faster warm starts)
# ─────────────────────────────────────────────────────────────────────────────
_compiled_rules = yara.compile(source=YARA_RULES)
 
 
# ═════════════════════════════════════════════════════════════════════════════
# Lambda handler: triggered by S3 ObjectCreated event
# ═════════════════════════════════════════════════════════════════════════════
def lambda_handler(event, context):
    print("S3 scan event received.")
 
    # 1. Parse S3 event
    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key    = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])
    except (KeyError, IndexError):
        return {"statusCode": 400, "body": "Invalid S3 event structure"}
 
    print(f"Scanning: s3://{bucket}/{key}")
 
    # 2. Size guard before loading into memory (M6 fix)
    try:
        head = s3_client.head_object(Bucket=bucket, Key=key)
        size = head.get('ContentLength', 0)
    except ClientError as e:
        return {"statusCode": 500, "body": f"head_object failed: {e}"}
 
    if size > MAX_SCAN_BYTES:
        print(f"⚠️ File too large to scan in memory ({size} bytes). Tagging for manual review.")
        s3_client.put_object_tagging(
            Bucket=bucket, Key=key,
            Tagging={'TagSet': [
                {'Key': 'SecurityStatus', 'Value': 'PENDING_LARGE_FILE_REVIEW'},
            ]}
        )
        return {"statusCode": 200, "body": "File exceeds scan size limit — flagged for manual review"}
 
    # 3. Download file into memory
    try:
        obj          = s3_client.get_object(Bucket=bucket, Key=key)
        file_content = obj['Body'].read()
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchKey':
            print(f"Object {key} was deleted before scanning — skipping.")
            return {"statusCode": 200, "body": "Object no longer exists"}
        return {"statusCode": 500, "body": f"get_object failed: {e}"}
 
    # 4. Run YARA scan
    matches = _compiled_rules.match(data=file_content)
 
    # 5a. THREAT DETECTED — quarantine
    if matches:
        matched_rule = matches[0].rule
        print(f"🚨 THREAT [{matched_rule}] in {key}. Quarantining...")
 
        # H1 fix: MOVE the object to an isolated quarantine bucket
        try:
            quarantine_key = f"quarantined/{bucket}/{key}"
            s3_client.copy_object(
                CopySource={'Bucket': bucket, 'Key': key},
                Bucket=QUARANTINE_BUCKET,
                Key=quarantine_key,
            )
            s3_client.delete_object(Bucket=bucket, Key=key)
            print(f"✅ Object moved to s3://{QUARANTINE_BUCKET}/{quarantine_key}")
        except ClientError as e:
            print(f"❌ Quarantine move failed: {e}. Falling back to tag-only.")
            # If move fails, at least tag it in-place so the UI still shows it
            s3_client.put_object_tagging(
                Bucket=bucket, Key=key,
                Tagging={'TagSet': [
                    {'Key': 'SecurityStatus', 'Value': 'QUARANTINED'},
                    {'Key': 'ThreatType',     'Value': matched_rule},
                ]}
            )
 
        # H5 fix: 'service' field now written so dashboard routes it correctly
        table = dynamodb.Table(TABLE_NAME)
        table.put_item(Item={
            'tenant_id':    bucket,
            'threat_id':    f"{bucket}::{key}",
            'service':      'Malware',          # ← was missing; now present
            'status':       'QUARANTINED',
            'file_key':     key,
            'yara_match':   matched_rule,
            'quarantine_key': f"s3://{QUARANTINE_BUCKET}/quarantined/{bucket}/{key}",
            'resolution':   'PENDING_ADMIN_REVIEW',
        })
        return {"statusCode": 200, "body": f"Quarantined: {matched_rule}"}
 
    # 5b. CLEAN
    print(f"✅ {key} is clean.")
    s3_client.put_object_tagging(
        Bucket=bucket, Key=key,
        Tagging={'TagSet': [{'Key': 'SecurityStatus', 'Value': 'CLEAN'}]}
    )
    return {"statusCode": 200, "body": "File clean"}
 
 
# ═════════════════════════════════════════════════════════════════════════════
# EC2 Security Scan
# ═════════════════════════════════════════════════════════════════════════════
def run_ec2_security_scan():
    """
    Scans all EC2 instances in SCAN_REGION for:
      - IMDSv1 active (SSRF risk)
      - Public IP assigned without a Sentinel-Exception tag
 
    H3 fix: paginator used — all instances retrieved, not just page 1.
    """
    ec2 = boto3.client('ec2', region_name=SCAN_REGION)
 
    try:
        paginator     = ec2.get_paginator('describe_instances')
        active_threats = []
        scanned_count  = 0
 
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    state = instance['State']['Name']
                    if state in ['terminated', 'shutting-down']:
                        continue
 
                    scanned_count += 1
                    instance_id = instance['InstanceId']
 
                    # H6 fix: check for exception tag before flagging
                    tags         = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
                    has_exception = tags.get('Sentinel-Exception') == 'Approved'
 
                    # CHECK 1: IMDSv1 / SSRF
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required' and not has_exception:
                        active_threats.append({
                            'service':      'EC2',
                            'resource_id':  instance_id,
                            'threat_type':  'IMDSv1 Active (SSRF Risk)',
                            'severity':     'CRITICAL',
                            'resolution':   'Enforce IMDSv2 to require session tokens.'
                        })
 
                    # CHECK 2: Public IP (L4 fix: re-enabled with tag exception)
                    public_ip = instance.get('PublicIpAddress')
                    if public_ip and not has_exception:
                        active_threats.append({
                            'service':      'EC2',
                            'resource_id':  instance_id,
                            'threat_type':  f'Public IP Assigned ({public_ip})',
                            'severity':     'HIGH',
                            'resolution':   'Move to a private subnet and use an ALB/Bastion. '
                                            'Tag with Sentinel-Exception:Approved if intentional.'
                        })
 
        return {
            'status':            'success',
            'instances_scanned': scanned_count,
            'threats_found':     len(active_threats),
            'threat_details':    active_threats
        }
 
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
 
 
def remediate_imdsv1_vulnerability(instance_id: str) -> dict:
    """
    Enforces IMDSv2 on a target EC2 instance.
    H6 fix: checks for Sentinel-Exception tag before acting.
    """
    ec2 = boto3.client('ec2', region_name=SCAN_REGION)
    try:
        # Respect exception tag
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        instance = desc['Reservations'][0]['Instances'][0]
        tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
        if tags.get('Sentinel-Exception') == 'Approved':
            return {
                'status':  'skipped',
                'message': f'{instance_id} has Sentinel-Exception:Approved tag — not remediating.'
            }
 
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpEndpoint='enabled'
        )
        return {
            'status':  'success',
            'message': f'IMDSv2 enforced on {instance_id}. SSRF vector neutralized.'
        }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
 
 
# ═════════════════════════════════════════════════════════════════════════════
# VPC / Security Group Scan
# ═════════════════════════════════════════════════════════════════════════════
def run_vpc_network_scan():
    """
    Scans all Security Groups for open SSH (22) / RDP (3389) to the internet.
    H3  fix: paginator used — all SGs retrieved, not just page 1.
    M11 fix: checks both IPv4 0.0.0.0/0 AND IPv6 ::/0
    H6  fix: SGs tagged Sentinel-Exception:Approved are skipped.
    """
    ec2 = boto3.client('ec2', region_name=SCAN_REGION)
 
    try:
        paginator       = ec2.get_paginator('describe_security_groups')
        network_threats = []
        scanned_count   = 0
 
        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                scanned_count += 1
                sg_id   = sg['GroupId']
                sg_name = sg['GroupName']
 
                tags         = {t['Key']: t['Value'] for t in sg.get('Tags', [])}
                has_exception = tags.get('Sentinel-Exception') == 'Approved'
                if has_exception:
                    continue
 
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port   = rule.get('ToPort')
 
                    if from_port not in [22, 3389] and to_port not in [22, 3389]:
                        continue
 
                    port_name = "SSH" if from_port == 22 else "RDP"
 
                    # M11 fix: check IPv4
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            network_threats.append({
                                'resource_id': sg_id,
                                'sg_name':     sg_name,
                                'threat_type': f"Open {port_name} (Port {from_port}) to Internet (0.0.0.0/0)",
                                'resolution':  f"Restrict {port_name} to a trusted IP or VPN.",
                                'proto':       'ipv4',
                            })
 
                    # M11 fix: check IPv6
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            network_threats.append({
                                'resource_id': sg_id,
                                'sg_name':     sg_name,
                                'threat_type': f"Open {port_name} (Port {from_port}) to Internet (::/0 IPv6)",
                                'resolution':  f"Restrict {port_name} to a trusted IPv6 prefix or VPN.",
                                'proto':       'ipv6',
                            })
 
        return {
            'status':        'success',
            'scanned_count': scanned_count,
            'threats':       network_threats
        }
 
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
 
 
def remediate_open_management_ports(sg_id: str) -> dict:
    """
    Revokes open SSH/RDP rules for both IPv4 and IPv6 on the given SG.
    H6  fix: checks for Sentinel-Exception tag before acting.
    M11 fix: revokes both CidrIp 0.0.0.0/0 and CidrIpv6 ::/0.
    """
    ec2 = boto3.client('ec2', region_name=SCAN_REGION)
 
    # H6 fix: exception tag check
    try:
        desc_sg = ec2.describe_security_groups(GroupIds=[sg_id])
        sg      = desc_sg['SecurityGroups'][0]
        tags    = {t['Key']: t['Value'] for t in sg.get('Tags', [])}
        if tags.get('Sentinel-Exception') == 'Approved':
            return {
                'status':  'skipped',
                'message': f'{sg_id} has Sentinel-Exception:Approved tag — not remediating.'
            }
    except Exception as e:
        return {'status': 'error', 'message': f'Could not read SG tags: {e}'}
 
    success_ports = []
 
    for port in [22, 3389]:
        # IPv4 revocation
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort':   port,
                    'ToPort':     port,
                    'IpRanges':   [{'CidrIp': '0.0.0.0/0'}],
                }]
            )
            success_ports.append(f"{port}/IPv4")
        except ClientError as e:
            if 'InvalidPermission.NotFound' not in str(e):
                return {'status': 'error', 'message': str(e)}
 
        # IPv6 revocation (M11 fix)
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort':   port,
                    'ToPort':     port,
                    'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
                }]
            )
            success_ports.append(f"{port}/IPv6")
        except ClientError as e:
            if 'InvalidPermission.NotFound' not in str(e):
                return {'status': 'error', 'message': str(e)}
 
    if success_ports:
        return {
            'status':  'success',
            'message': f"Ports {', '.join(success_ports)} locked down on {sg_id}."
        }
    return {
        'status':  'success',
        'message': f"No open SSH/RDP rules found on {sg_id}."
    }