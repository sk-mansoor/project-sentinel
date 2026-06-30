import streamlit as st
import streamlit.components.v1 as components
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import pandas as pd
from datetime import datetime, timedelta
import extra_streamlit_components as stx

# ==========================================
# PAGE CONFIGURATION (Must be at the very top)
# ==========================================
st.set_page_config(page_title="Project Sentinel Core", layout="wide")

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def check_logging_status(trail_name):
    """Interrogates AWS in real-time to see if logging is currently active."""
    try:
        client = boto3.client('cloudtrail', region_name='us-east-1')
        status = client.get_trail_status(Name=trail_name)
        return status.get('IsLogging', False)
    except Exception as e:
        return False

@st.cache_data(ttl=300)
def generate_csv_audit_report():
    """Fetches real CloudTrail events and formats them for export."""
    client = boto3.client('cloudtrail', region_name='us-east-1')
    start_time = datetime.now() - timedelta(days=1)
    
    try:
        response = client.lookup_events(
            StartTime=start_time,
            MaxResults=100
        )
        
        events_list = []
        for event in response.get('Events', []):
            events_list.append({
                "Event Time (UTC)": event.get('EventTime'),
                "Event Name": event.get('EventName'),
                "Username": event.get('Username'),
                "Access Key ID": event.get('AccessKeyId', 'N/A'),
                "Resource Type": event.get('Resources', [{}])[0].get('ResourceType', 'N/A') if event.get('Resources') else 'N/A'
            })
            
        if not events_list:
            df = pd.DataFrame([{"Status": "No CloudTrail events found in the last 24 hours."}])
        else:
            df = pd.DataFrame(events_list)
            
        return df.to_csv(index=False).encode('utf-8')
        
    except Exception as e:
        df = pd.DataFrame([{"Error Generation Report": str(e)}])
        return df.to_csv(index=False).encode('utf-8')

def get_encryption_status(trail_name):
    client = boto3.client('cloudtrail', region_name='us-east-1')
    try:
        response = client.describe_trails(trailNameList=[trail_name])
        if 'trailList' in response and len(response['trailList']) > 0:
            trail = response['trailList'][0]
            if 'KmsKeyId' in trail:
                return "Enabled", "AES-256"
            else:
                return "Disabled", "CRITICAL"
        else:
            return "Not Found", "Error" 
    except Exception as e:
        print(f"DEBUG: CloudTrail API Error: {e}") 
        return "Unknown", "Error"

def fetch_prowler_reports_from_s3():
    bucket_name = "sentinel-prowler-archive"
    s3_client = boto3.client('s3', region_name='us-east-1')
    reports = []
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                file_type = "CSV Data" if key.endswith('.csv') else "HTML Report"
                reports.append({
                    "File": key,
                    "Date": key.split('/')[0] if '/' in key else "Root",
                    "Type": file_type,
                    "Size": f"{round(obj['Size'] / 1024, 2)} KB"
                })
        else:
            st.warning(f"Connected to '{bucket_name}', but AWS says the bucket is empty.")
    except Exception as e:
        st.error(f"🚨 S3 Access Error: {str(e)}") 
    return reports, bucket_name

# ==========================================
# CONFIGURATION & COOKIE MANAGER
# ==========================================
COGNITO_REGION = "us-east-1"
USER_POOL_ID = "us-east-1_ai2btwKN7"
CLIENT_ID = "2huqdlahes7qii73s3nrb56e38"

cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
cookie_manager = stx.CookieManager()

# Initialize Session States
if "auth_step" not in st.session_state:
    st.session_state.auth_step = "LOGIN"
if "session_token" not in st.session_state:
    st.session_state.session_token = None
if "username" not in st.session_state:
    st.session_state.username = None
if "totp_secret" not in st.session_state:
    st.session_state.totp_secret = None
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# --- NEW: Check for Persistent Login Cookie ---
import time
time.sleep(0.2)
auth_token = cookie_manager.get(cookie="auth_token")
if auth_token == "logged_in":
    st.session_state.authenticated = True
    st.session_state.auth_step = "DONE"
    if not st.session_state.username:
        st.session_state.username = "SOC_Analyst (Session Restored)"

# ==========================================
# AUTHENTICATION LOGIC
# ==========================================
def initiate_login(username, password):
    try:
        response = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password}
        )
        if response.get("ChallengeName") == "MFA_SETUP":
            setup_resp = cognito_client.associate_software_token(Session=response["Session"])
            st.session_state.totp_secret = setup_resp["SecretCode"]
            st.session_state.session_token = setup_resp["Session"]
            st.session_state.username = username
            st.session_state.auth_step = "SETUP_MFA"
            return True, "Device Enrollment Required"
        elif response.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
            st.session_state.session_token = response["Session"]
            st.session_state.username = username
            st.session_state.auth_step = "MFA_CHALLENGE"
            return True, "MFA Code Required"
        elif response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
            st.session_state.session_token = response["Session"]
            st.session_state.username = username
            st.session_state.auth_step = "NEW_PASSWORD"
            return True, "Password Change Required"
        elif "AuthenticationResult" in response:
            st.session_state.authenticated = True
            st.session_state.auth_step = "DONE"
            return True, "Login Successful"
    except ClientError as e:
        return False, e.response['Error']['Message']
    return False, "Unknown authentication state."

def set_new_password(new_password):
    try:
        response = cognito_client.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=st.session_state.session_token,
            ChallengeResponses={
                "USERNAME": st.session_state.username,
                "NEW_PASSWORD": new_password
            }
        )
        if response.get("ChallengeName") == "MFA_SETUP":
            setup_resp = cognito_client.associate_software_token(Session=response["Session"])
            st.session_state.totp_secret = setup_resp["SecretCode"]
            st.session_state.session_token = setup_resp["Session"]
            st.session_state.auth_step = "SETUP_MFA"
            return True, "Device Enrollment Required"
        elif "AuthenticationResult" in response:
            st.session_state.authenticated = True
            st.session_state.auth_step = "DONE"
            return True, "Login Successful"
    except ClientError as e:
        return False, e.response['Error']['Message']
    return False, "Failed to update password."

def verify_mfa_setup(mfa_code):
    try:
        verify_resp = cognito_client.verify_software_token(
            Session=st.session_state.session_token,
            UserCode=mfa_code,
            FriendlyDeviceName="SentinelAdmin"
        )
        if verify_resp["Status"] == "SUCCESS":
            cognito_client.respond_to_auth_challenge(
                ClientId=CLIENT_ID,
                ChallengeName="MFA_SETUP",
                Session=verify_resp["Session"],
                ChallengeResponses={"USERNAME": st.session_state.username}
            )
            st.session_state.authenticated = True
            st.session_state.auth_step = "DONE"
            return True, "MFA Successfully Configured"
    except ClientError as e:
        return False, e.response['Error']['Message']
    return False, "Verification failed."

def verify_mfa_code(mfa_code):
    try:
        response = cognito_client.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=st.session_state.session_token,
            ChallengeResponses={
                "USERNAME": st.session_state.username,
                "SOFTWARE_TOKEN_MFA_CODE": mfa_code
            }
        )
        if "AuthenticationResult" in response:
            st.session_state.authenticated = True
            st.session_state.auth_step = "DONE"
            return True, "Access Granted"
    except ClientError as e:
        return False, e.response['Error']['Message']
    return False, "Invalid Code."

# ==========================================
# UI RENDERING ENGINE
# ==========================================
st.title("🛡️ Project Sentinel - Enterprise Cloud Guard")

# VIEW 1: Login
if st.session_state.auth_step == "LOGIN":
    st.subheader("Central Administrator Authentication")
    with st.form("login_form"):
        username = st.text_input("Admin Username")
        password = st.text_input("Password", type="password")
        dev_mode = st.checkbox("🛠️ Dev Mode: Bypass MFA (For live demo/testing)")
        submit = st.form_submit_button("Initiate Secure Session")
        
        if submit:
            if dev_mode:
                st.session_state.username = username.strip()
                st.session_state.authenticated = True
                st.session_state.auth_step = "DONE"
                cookie_manager.set("auth_token", "logged_in", max_age=86400) # Save Cookie
                import time       # <--- ADD THIS
                time.sleep(0.5)
                st.rerun()
            else:
                success, message = initiate_login(username.strip(), password.strip())
                if success:
                    if st.session_state.auth_step == "DONE":
                        cookie_manager.set("auth_token", "logged_in", max_age=86400)
                        import time       # <--- ADD THIS
                        time.sleep(0.5)
                    st.rerun()
                else: 
                    st.error(message)

# VIEW 1.5: Force Password Change
elif st.session_state.auth_step == "NEW_PASSWORD":
    st.subheader("🔒 Action Required: Change Temporary Password")
    st.warning("Your administrator provided a temporary password. You must set a new permanent password to continue.")
    with st.form("new_password_form"):
        new_password = st.text_input("New Permanent Password", type="password")
        if st.form_submit_button("Update Password"):
            success, message = set_new_password(new_password)
            if success: 
                if st.session_state.auth_step == "DONE":
                    cookie_manager.set("auth_token", "logged_in", max_age=86400)
                st.rerun()
            else: 
                st.error(message)

# VIEW 2: First-time MFA Setup
elif st.session_state.auth_step == "SETUP_MFA":
    st.subheader("🔒 Action Required: Configure Authenticator App")
    st.warning("1. Open Google Authenticator or Authy on your phone.")
    st.warning("2. Select 'Add Account' -> 'Enter Setup Key'.")
    st.info(f"**Account Name:** SentinelAdmin\n\n**Secret Key:** `{st.session_state.totp_secret}`")
    st.write("3. Enter the 6-digit code generated by the app below to finalize enrollment.")
    with st.form("setup_mfa_form"):
        mfa_code = st.text_input("6-Digit Verification Code", max_chars=6)
        if st.form_submit_button("Verify & Enroll Device"):
            success, message = verify_mfa_setup(mfa_code)
            if success:
                cookie_manager.set("auth_token", "logged_in", max_age=86400)
                st.rerun()
            else: 
                st.error(message)

# VIEW 3: Standard MFA Login
elif st.session_state.auth_step == "MFA_CHALLENGE":
    st.subheader("Multi-Factor Authentication Required")
    with st.form("mfa_form"):
        mfa_code = st.text_input("6-Digit Authenticator Code", max_chars=6)
        if st.form_submit_button("Verify Identity"):
            success, message = verify_mfa_code(mfa_code)
            if success:
                cookie_manager.set("auth_token", "logged_in", max_age=86400)
                st.rerun()
            else: 
                st.error(message)

# VIEW 4: Protected Dashboard
elif st.session_state.auth_step == "DONE" and st.session_state.authenticated:
    st.sidebar.success(f"Authenticated as: {st.session_state.username}")
    
    # Logout Logic
    if st.sidebar.button("Terminate Session"):
        cookie_manager.delete("auth_token")
        st.session_state.clear()
        st.rerun()

    # --- EXCEPTION APPROVAL WORKFLOW ---
    if st.query_params.get("action") == "override":
        target_bucket = st.query_params.get("bucket")
        st.error(f"⚠️ EXCEPTION REQUEST: Override Security Controls for `{target_bucket}`?")
        st.warning("Approving this will attach a Whitelist Tag to the bucket, disable public access blocks, and instruct the auto-remediator to ignore this bucket moving forward.")
        
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("✅ Approve & Make Public", use_container_width=True):
                s3_c = boto3.client('s3', region_name=COGNITO_REGION)
                s3_c.put_bucket_tagging(
                    Bucket=target_bucket, 
                    Tagging={'TagSet': [
                        {'Key': 'Sentinel-Override', 'Value': 'Approved'},
                        {'Key': 'ApprovedBy', 'Value': st.session_state.username}
                    ]}
                )
                s3_c.delete_public_access_block(Bucket=target_bucket)
                try:
                    sns_c = boto3.client('sns', region_name=COGNITO_REGION)
                    SNS_ARN = "arn:aws:sns:us-east-1:225119180791:sentinel-security-alerts" 
                    sns_c.publish(
                        TopicArn=SNS_ARN,
                        Subject="⚠️ Sentinel Audit: Security Exception Granted",
                        Message=f"AUDIT LOG:\n\nAdministrator '{st.session_state.username}' has explicitly granted a security exception for bucket '{target_bucket}'.\n\nThe bucket is now publicly accessible."
                    )
                except Exception as e:
                    st.toast(f"Failed to send audit alert: {e}")
                
                st.success("Bucket Whitelisted and made Public! Audit log recorded.")
                st.query_params.clear() 
                st.rerun()
        with col_b:
            if st.button("❌ Deny & Keep Secure", use_container_width=True):
                st.success("Request Denied. Bucket remains secure.")
                st.query_params.clear() 
                st.rerun()
        st.divider()

    # Fetch live incident data from DynamoDB
    try:
        db_resource = boto3.resource('dynamodb', region_name=COGNITO_REGION)
        table = db_resource.Table("sentinel-tenant-registry")
        scan_response = table.scan()
        incidents = scan_response.get('Items', [])
    except Exception as e:
        incidents = []
        st.sidebar.error(f"Registry Sync Error: {str(e)}")

    # Create navigation tabs
    tab_summary, tab_iam, tab_cspm, tab_malware, tab_cloudtrial = st.tabs([
        "📊 Enterprise Posture", 
        "🔐 IAM Security",
        "⚙️ SaaS CSPM Engine", 
        "🔬 Serverless Malware Quarantine",
        "🪪 CloudTrail Integrity"
    ])
    
    with tab_summary:
        st.markdown("### Global Security Matrix (5-Service Core)")
        total_threats = len(incidents)
        
        compliance_score = "Pending..."
        chart_data = {"Date": ["Today"], "Score": [0]} 
        
        try:
            compliance_table = db_resource.Table("sentinel-compliance-history")
            
            # --- BUG FIX: ALWAYS PULL THE CENTRAL 'admin' TENANT DATA FOR THE DASHBOARD ---
            query_user = "admin" 
            
            comp_response = compliance_table.query(
                KeyConditionExpression=Key('TenantID').eq(query_user)
            )
            comp_items = comp_response.get('Items', [])
            
            if comp_items:
                comp_items.sort(key=lambda x: x['ScanDate'])
                latest_score = int(comp_items[-1]['ComplianceScore'])
                compliance_score = f"{latest_score}%"
                
                chart_data = {
                    "Date": [item['ScanDate'][5:] for item in comp_items], 
                    "Score": [int(item['ComplianceScore']) for item in comp_items]
                }
        except Exception as e:
            st.error(f"Failed to fetch compliance history: {str(e)}")
            comp_items = []
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("CIS Benchmark Compliance", value=compliance_score, delta="Daily Scan: LIVE", delta_color="normal")
        #with col2:
          # st.metric("Active Configuration Drifts", value="0")
        with col3:
            st.metric("Active Quarantined Threats", value=str(total_threats))

        st.divider()
        st.markdown("#### Continuous Assessment Timeline")
        st.line_chart(chart_data, x="Date", y="Score")
        st.divider()
        
        st.markdown("#### Service Health Status")
        s_col1, s_col2, s_col3, s_col4, s_col5 = st.columns(5)
        
        affected_services = [item.get('service', 'S3').upper() for item in incidents]

        if 'IAM' in affected_services: s_col1.error("IAM: Vulnerable")
        else: s_col1.success("IAM: Secure")

        if 'S3' in affected_services: s_col2.error("S3: Under Attack")
        else: s_col2.success("S3: Secure")

        if 'EC2' in affected_services: s_col3.error("EC2: Vulnerable")
        else: s_col3.success("EC2: Secure")

        if 'VPC' in affected_services: s_col4.error("VPC: Drift Detected")
        else: s_col4.success("VPC: Secure")

        if 'CLOUDTRAIL' in affected_services: s_col5.error("CloudTrail: Offline")
        else: s_col5.success("CloudTrail: Secure")

        st.divider()
        st.subheader("📁 Automated Compliance Report Archive")
        st.markdown("Live interactive view of the latest automated Prowler security scan.")
        
        target_bucket = "sentinel-prowler-archive"
        s3_client = boto3.client('s3', region_name='us-east-1')
        
        try:
            response = s3_client.list_objects_v2(Bucket=target_bucket)
            if 'Contents' in response:
                sorted_files = sorted(response['Contents'], key=lambda obj: obj['LastModified'], reverse=True)
                html_files = [f for f in sorted_files if f['Key'].endswith('.html')]
                
                if html_files:
                    latest_html_key = html_files[0]['Key']
                    report_date = latest_html_key.split('/')[0]
                    
                    col_info, col_fullscreen, col_download = st.columns([2.5, 1.25, 1.25])
                    with col_info:
                        st.success(f"✅ Successfully loaded latest scan from: **{report_date}**")
                    
                    presigned_url = s3_client.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': target_bucket, 'Key': latest_html_key},
                        ExpiresIn=3600
                    )
                    
                    with col_fullscreen:
                        st.link_button("↗️ Open Full Screen", url=presigned_url, use_container_width=True)
                        
                    with col_download:
                        st.link_button("💾 Download HTML", url=presigned_url, use_container_width=True)
                    
                    st.write("### 🔬 Interactive Report")
                    with st.spinner("Rendering full compliance document..."):
                        file_obj = s3_client.get_object(Bucket=target_bucket, Key=latest_html_key)
                        raw_html = file_obj['Body'].read().decode('utf-8')
                        
                        with st.expander("👁️ Expand Full Prowler Report", expanded=True):
                            st.components.v1.iframe(presigned_url, height=800, scrolling=True)
                    
                    if len(html_files) > 1:
                        st.divider()
                        st.write("### 🗄️ Historical Reports (7-Day Retention)")
                        for old_file in html_files[1:]:
                            old_date = old_file['Key'].split('/')[0]
                            old_size = f"{round(old_file['Size'] / 1024, 2)} KB"
                            
                            c_date, c_size, c_btn = st.columns([2, 2, 2])
                            with c_date: st.write(f"📅 {old_date}")
                            with c_size: st.write(f"⚖️ {old_size}")
                            with c_btn:
                                old_url = s3_client.generate_presigned_url(
                                    'get_object',
                                    Params={'Bucket': target_bucket, 'Key': old_file['Key']},
                                    ExpiresIn=3600
                                )
                                st.link_button("Download", url=old_url, key=old_file['Key'])
                else:
                    st.info("No HTML reports found in the bucket yet.")
        except Exception as e:
            st.error(f"Failed to fetch report: {str(e)}")       
            
    # -----------------------------------------
    # TAB 2: IAM Security Posture
    # -----------------------------------------
    with tab_iam:
        st.subheader("Identity & Access Management (IAM) Posture")
        st.markdown("Live monitoring of credential stagnation, privilege escalation vectors, and root account activity.")
        
        live_stale_keys = str(comp_items[0].get('StaleKeys', 0)) if comp_items else "0"
        live_missing_mfa = str(comp_items[0].get('MissingMFA', 0)) if comp_items else "0"

        try:
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            registry_table = dynamodb.Table('sentinel-tenant-registry')
            incident_items = registry_table.scan().get('Items', [])
        except Exception as e:
            incident_items = []
            st.warning(f"Database Connection Error: {str(e)}")

        iam_threat_count = sum(1 for item in incident_items if item.get('service') == 'IAM')

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Active Root Logins", value=iam_threat_count, delta="Critical Threat" if iam_threat_count > 0 else "Secured", delta_color="inverse" if iam_threat_count > 0 else "normal")
        with col2:
            st.metric(label="Stale Access Keys (>90 Days)", value=live_stale_keys, delta="Action Required" if int(live_stale_keys) > 0 else "Secured", delta_color="inverse")
        with col3:
            st.metric(label="Users without MFA", value=live_missing_mfa, delta="Critical" if int(live_missing_mfa) > 0 else "Secured", delta_color="inverse")
            
        st.divider()
        st.write("### Real-Time IAM Threat Log")
        
        iam_threats = [item for item in incident_items if item.get('service') == 'IAM']
        
        if iam_threats:
            for threat in iam_threats:
                st.error(f"🚨 **{threat.get('file_key')}**")
                st.write(f"**Action Required:** {threat.get('resolution')}")
        else:
            st.success("No active identity threats detected in the current session.")

    # -----------------------------------------
    # TAB 3: CSPM
    # -----------------------------------------
    with tab_cspm:
        st.markdown("### Cloud Security Posture Management (CSPM)")
        st.write("Actively scanning tenant storage architecture for baseline compliance...")
        
        s3_client = boto3.client('s3', region_name=COGNITO_REGION)
        sns_client = boto3.client('sns', region_name=COGNITO_REGION)
        
        try:
            buckets = s3_client.list_buckets()['Buckets']
            tenant_bucket = next((b['Name'] for b in buckets if b['Name'].startswith('sentinel-tenant-data-')), None)
        except Exception:
            tenant_bucket = None
            
        if tenant_bucket:
            st.info(f"Target Acquired: `{tenant_bucket}`")
            try:
                posture = s3_client.get_public_access_block(Bucket=tenant_bucket)
                is_secure = posture['PublicAccessBlockConfiguration']['BlockPublicAcls']
            except Exception:
                is_secure = False 
                
            if is_secure:
                st.success("✅ Secure Baseline Confirmed: Maximum Public Access Blocks Enforced.")
            else:
                st.warning("⚠️ VULNERABILITY DETECTED: Storage bucket is lacking strict public access restrictions.")
                if st.button("Remediate & Enforce Secure Conditions"):
                    try:
                        s3_client.put_public_access_block(
                            Bucket=tenant_bucket,
                            PublicAccessBlockConfiguration={
                                'BlockPublicAcls': True,
                                'IgnorePublicAcls': True,
                                'BlockPublicPolicy': True,
                                'RestrictPublicBuckets': True
                            }
                        )
                        st.success("Remediation Successful! Bucket locked down.")
                        
                        SNS_ARN = "arn:aws:sns:us-east-1:225119180791:sentinel-security-alerts" 
                        sns_client.publish(
                            TopicArn=SNS_ARN,
                            Subject="🛡️ Sentinel Alert: Posture Remediated",
                            Message=f"Project Sentinel CSPM Engine has successfully remediated a vulnerability.\n\nTarget: {tenant_bucket}\nAction: Enforced Strict Public Access Blocks.\nStatus: SECURE."
                        )
                        st.toast("Notification Email Dispatched via AWS SNS")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Remediation Failed: {str(e)}")
        else:
            st.error("No active tenant buckets found to scan.")

    # -----------------------------------------
    # TAB 4: Serverless Malware
    # -----------------------------------------
    with tab_malware:
        st.markdown("### Live Serverless Inspection Queue")
        if not incidents:
            st.success("Zero-Threat Environment: No malicious artifacts detected.")
        else:
            st.error(f"🚨 ALERT: {len(incidents)} Malicious Artifacts Quarantined.")
            for item in incidents:
                with st.expander(f"🔴 Threat Isolated: {item.get('file_key')}", expanded=True):
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**Tenant Domain:**\n`{item.get('tenant_id')}`")
                    c2.markdown(f"**Status:**\n`{item.get('status')}`")
                    c3.markdown(f"**Action Required:**\n`{item.get('resolution')}`")
   
    # -----------------------------------------
    # TAB 5: CloudTrail Integrity
    # -----------------------------------------
    with tab_cloudtrial:
        st.subheader("CloudTrail Integrity & Audit Monitor")
        st.markdown("Real-time surveillance of log tampering, audit trail deletion, and infrastructure sabotage.")

        ct_incidents = [item for item in incident_items if item.get('service') == 'CloudTrail']
        tamper_count = len(ct_incidents)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Tamper Events (24h)", value=tamper_count, delta="Critical" if tamper_count > 0 else "Secure", delta_color="inverse")
        with col2:
            status, cipher = get_encryption_status('sentinel-global-audit')
            st.metric(label="Log Encryption", value=status, delta=cipher)
        with col3:
            is_logging_active = check_logging_status('sentinel-global-audit')
            if is_logging_active:
                st.metric(label="Logging Status", value="✅ Active", delta="Secure")
            else:
                st.metric(label="Logging Status", value="❌ STOPPED", delta="- CRITICAL", delta_color="inverse")

        if not is_logging_active:
            st.error("🚨 CRITICAL ALERT: CloudTrail logging is currently DISABLED. The environment is blind to API activity. Click 'Re-Enable CloudTrail Logging' immediately.")

        st.divider()
        st.write("### Active Audit Tamper Alerts")
        
        if ct_incidents:
            for incident in ct_incidents:
                with st.expander(f"⚠️ {incident.get('file_key')}", expanded=True):
                    st.warning(incident.get('resolution'))
                    st.caption(f"Event ID: {incident.get('incident_id')}")
        else:
            st.success("No active tampering detected. Audit trail is secure.")

        st.divider()
        st.write("### SOC Quick Response")
        col_a, col_b = st.columns(2)

        with col_a:
            if st.button("🛡️ Re-Enable CloudTrail Logging"):
                with st.spinner("Triggering remediation workflow..."):
                    try:
                        lambda_client = boto3.client('lambda', region_name='us-east-1')
                        lambda_client.invoke(
                            FunctionName='sentinel-remediate-cloudtrail',
                            InvocationType='RequestResponse'
                        )
                        st.toast("✅ Remediation successful! Audit trail restored.")
                        st.rerun() 
                    except Exception as e:
                        st.error(f"Failed to trigger remediation: {e}")

        with col_b:
            csv_export_data = generate_csv_audit_report()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button(
                label="📄 Download Full Audit Report",
                data=csv_export_data,
                file_name=f"Sentinel_Audit_Export_{timestamp}.csv",
                mime="text/csv",
            )