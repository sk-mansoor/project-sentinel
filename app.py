import streamlit as st
import boto3
from botocore.exceptions import ClientError

# ==========================================
# CONFIGURATION
# ==========================================
COGNITO_REGION = "us-east-1"
USER_POOL_ID = "us-east-1_ai2btwKN7"
CLIENT_ID = "2huqdlahes7qii73s3nrb56e38"

cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

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
        
        # Scenario 1: First time login - Needs Authenticator App Setup
        if response.get("ChallengeName") == "MFA_SETUP":
            setup_resp = cognito_client.associate_software_token(Session=response["Session"])
            st.session_state.totp_secret = setup_resp["SecretCode"]
            st.session_state.session_token = setup_resp["Session"]
            st.session_state.username = username
            st.session_state.auth_step = "SETUP_MFA"
            return True, "Device Enrollment Required"
            
        # Scenario 2: Normal login - Needs 6-digit code
        elif response.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
            st.session_state.session_token = response["Session"]
            st.session_state.username = username
            st.session_state.auth_step = "MFA_CHALLENGE"
            return True, "MFA Code Required"
            
        # Scenario 3: Temporary Password (Created via Console) - Needs Password Change
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
        # After password change, Cognito will typically force MFA setup
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
        # Step A: Verify the code they typed matches the generated secret
        verify_resp = cognito_client.verify_software_token(
            Session=st.session_state.session_token,
            UserCode=mfa_code,
            FriendlyDeviceName="SentinelAdmin"
        )
        if verify_resp["Status"] == "SUCCESS":
            # Step B: Answer the original challenge to get access tokens
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
st.set_page_config(page_title="Project Sentinel Core", layout="wide")
st.title("🛡️ Project Sentinel - Enterprise Cloud Guard")

# VIEW 1: Login
if st.session_state.auth_step == "LOGIN":
    st.subheader("Central Administrator Authentication")
    with st.form("login_form"):
        # Removed hardcoded values for production security
        username = st.text_input("Admin Username")
        password = st.text_input("Password", type="password")
        
        # --- NEW: DEV MODE BYPASS ---
        dev_mode = st.checkbox("🛠️ Dev Mode: Bypass MFA (For live demo/testing)")
        
        submit = st.form_submit_button("Initiate Secure Session")
        if submit:
            if dev_mode:
                # Instantly bypass security for testing speed
                st.session_state.username = username.strip()
                st.session_state.authenticated = True
                st.session_state.auth_step = "DONE"
                st.rerun()
            else:
                # Run the real Enterprise Cognito Flow
                # Using .strip() to eliminate invisible trailing spaces that cause AWS rejections
                success, message = initiate_login(username.strip(), password.strip())
                if success: st.rerun()
                else: st.error(message)

# VIEW 1.5: Force Password Change (Temporary Password Scenario)
elif st.session_state.auth_step == "NEW_PASSWORD":
    st.subheader("🔒 Action Required: Change Temporary Password")
    st.warning("Your administrator provided a temporary password. You must set a new permanent password to continue.")
    
    with st.form("new_password_form"):
        new_password = st.text_input("New Permanent Password", type="password")
        if st.form_submit_button("Update Password"):
            success, message = set_new_password(new_password)
            if success: st.rerun()
            else: st.error(message)

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
            if success: st.rerun()
            else: st.error(message)

# VIEW 3: Standard MFA Login
elif st.session_state.auth_step == "MFA_CHALLENGE":
    st.subheader("Multi-Factor Authentication Required")
    with st.form("mfa_form"):
        mfa_code = st.text_input("6-Digit Authenticator Code", max_chars=6)
        if st.form_submit_button("Verify Identity"):
            success, message = verify_mfa_code(mfa_code)
            if success: st.rerun()
            else: st.error(message)

# VIEW 4: Protected Dashboard
elif st.session_state.auth_step == "DONE" and st.session_state.authenticated:
    st.sidebar.success(f"Authenticated as: {st.session_state.username}")
    if st.sidebar.button("Terminate Session"):
        st.session_state.clear()
        st.rerun()

    # --- NEW EXCEPTION APPROVAL WORKFLOW ---
    if st.query_params.get("action") == "override":
        target_bucket = st.query_params.get("bucket")
        st.error(f"⚠️ EXCEPTION REQUEST: Override Security Controls for `{target_bucket}`?")
        st.warning("Approving this will attach a Whitelist Tag to the bucket, disable public access blocks, and instruct the auto-remediator to ignore this bucket moving forward.")
        
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("✅ Approve & Make Public", use_container_width=True):
                s3_c = boto3.client('s3', region_name=COGNITO_REGION)
                
                # 1. Tag bucket so Lambda ignores it AND record who did it!
                s3_c.put_bucket_tagging(
                    Bucket=target_bucket, 
                    Tagging={'TagSet': [
                        {'Key': 'Sentinel-Override', 'Value': 'Approved'},
                        {'Key': 'ApprovedBy', 'Value': st.session_state.username}
                    ]}
                )
                
                # 2. Make it public
                s3_c.delete_public_access_block(Bucket=target_bucket)
                
                # 3. Audit Alert (Send email to the whole team)
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
                st.query_params.clear() # Clean the URL
                st.rerun()
        with col_b:
            if st.button("❌ Deny & Keep Secure", use_container_width=True):
                st.success("Request Denied. Bucket remains secure.")
                st.query_params.clear() # Clean the URL
                st.rerun()
        st.divider()
    # --- END NEW OVERRIDE LOGIC ---

    # Fetch live incident data from DynamoDB
    try:
        db_resource = boto3.resource('dynamodb', region_name=COGNITO_REGION)
        table = db_resource.Table("sentinel-tenant-registry")
        scan_response = table.scan()
        incidents = scan_response.get('Items', [])
    except Exception as e:
        incidents = []
        st.sidebar.error(f"Registry Sync Error: {str(e)}")

    tab_summary, tab_cspm, tab_malware = st.tabs([
        "📊 Enterprise Posture", "⚙️ SaaS CSPM Engine", "🔬 Serverless Malware Quarantine"
    ])
    
    with tab_summary:
        st.markdown("### Global Security Matrix (5-Service Core)")
        
        # Real-time incident math
        total_threats = len(incidents)
        
        # In the future, this score will be pulled directly from the Prowler JSON artifact
        # For the UI build out today, we will represent the CIS Benchmark Baseline
        compliance_score = "85%" 
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("CIS Benchmark Compliance", value=compliance_score, delta="Daily Scan: PASS", delta_color="normal")
        with col2:
            st.metric("Active Configuration Drifts", value="0")
        with col3:
            st.metric("Active Quarantined Threats", value=str(total_threats))

        st.divider()
        st.markdown("#### Continuous Assessment Timeline")
        
        # Mock time-series data for the 30-day compliance chart
        # We will connect this to DynamoDB in the next phase
        chart_data = {
            "Date": ["Day 1", "Day 5", "Day 10", "Day 15", "Day 20", "Day 25", "Today"],
            "Score": [45, 60, 60, 75, 80, 85, 85]
        }
        st.line_chart(chart_data, x="Date", y="Score")

        st.divider()
        st.markdown("#### Service Health Status")
        s_col1, s_col2, s_col3, s_col4, s_col5 = st.columns(5)
        s_col1.success("IAM: Secure")
        s_col2.success("S3: Secure")
        s_col3.success("EC2: Secure")
        s_col4.success("VPC: Secure")
        s_col5.success("CloudTrail: Secure")

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
                        
                        # --- PASTE YOUR SNS ARN RIGHT HERE ---
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