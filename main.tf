terraform {
  required_version = ">= 1.0.0"
  
  backend "s3" {
    bucket  = "sentinel-tf-state-mtech123" # Matches your new bucket exactly
    key     = "core-infrastructure/terraform.tfstate"
    region  = "us-east-1"
    profile = "sentinel"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ==========================================
# 1. MULTI-TENANT REGISTRY (DYNAMODB)
# ==========================================
resource "aws_dynamodb_table" "sentinel_tenants" {
  name         = "sentinel-tenant-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"

  attribute {
    name = "tenant_id"
    type = "S"
  }

  tags = {
    Project     = "ProjectSentinel"
    Environment = "Dev"
  }
}

# ==========================================
# 2. IDENTITY GATEKEEPER (COGNITO WITH MFA)
# ==========================================
resource "aws_cognito_user_pool" "sentinel_auth" {
  name = "sentinel-admin-user-pool"

  alias_attributes          = ["email"]
  auto_verified_attributes = ["email"]

  # Enforce Enterprise Password Complexity
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  # Enforce TOTP Authenticator Apps MFA
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = {
    Project     = "ProjectSentinel"
    Environment = "Dev"
  }
}

resource "aws_cognito_user_pool_client" "streamlit_client" {
  name         = "sentinel-streamlit-dashboard"
  user_pool_id = aws_cognito_user_pool.sentinel_auth.id

  generate_secret     = false
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_PASSWORD_AUTH"
  ]

  supported_identity_providers = ["COGNITO"]
  
  # Streamlit integration configurations
  callback_urls        = ["http://localhost:8501", "https://localhost:8501"]
  logout_urls          = ["http://localhost:8501", "https://localhost:8501"]
  allowed_oauth_flows  = ["code"]
  allowed_oauth_scopes = ["openid", "email", "profile"]
}

# ==========================================
# 3. CENTRAL SECURITY EXECUTION CORE (IAM)
# ==========================================
resource "aws_iam_role" "sentinel_engine_role" {
  name = "sentinel-core-engine-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Project     = "ProjectSentinel"
    Environment = "Dev"
  }
}

# Base execution policy for CloudWatch logging and DynamoDB reading
resource "aws_iam_policy" "sentinel_base_policy" {
  name        = "sentinel-core-base-policy"
  description = "Allows Project Sentinel engine to log and read tenant registry metadata."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ]
        Effect   = "Allow"
        Resource = aws_dynamodb_table.sentinel_tenants.arn
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = "arn:aws:iam::*:role/SentinelTenantCrossAccountRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "engine_base_attach" {
  role       = aws_iam_role.sentinel_engine_role.name
  policy_arn = aws_iam_policy.sentinel_base_policy.arn
}

# ==========================================
# OUTPUTS FOR PHASE 2 INTEGRATION
# ==========================================
output "dynamodb_table_name" {
  value       = aws_dynamodb_table.sentinel_tenants.name
  description = "Name of the tenant registration database."
}

output "cognito_user_pool_id" {
  value       = aws_cognito_user_pool.sentinel_auth.id
  description = "Cognito User Pool ID for Streamlit integration."
}

output "cognito_client_id" {
  value       = aws_cognito_user_pool_client.streamlit_client.id
  description = "Cognito App Client ID for your frontend application."
}

output "core_engine_role_arn" {
  value       = aws_iam_role.sentinel_engine_role.arn
  description = "IAM Role ARN to assign to the scanning Lambda functions."
}

# ==========================================
# 4. TENANT TARGET ENVIRONMENT (S3)
# ==========================================
resource "random_id" "bucket_id" {
  byte_length = 4
}

resource "aws_s3_bucket" "tenant_storage" {
  bucket        = "sentinel-tenant-data-${random_id.bucket_id.hex}"
  force_destroy = true 
}

resource "aws_s3_bucket_versioning" "tenant_versioning" {
  bucket = aws_s3_bucket.tenant_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ==========================================
# 5. SERVERLESS MALWARE SCANNER (LAMBDA)
# ==========================================
data "archive_file" "scanner_zip" {
  type        = "zip"
  source_file = "scanner.py"
  output_path = "scanner.zip"
}

resource "aws_lambda_function" "malware_scanner" {
  filename         = "scanner.zip"
  function_name    = "sentinel-malware-scanner"
  role             = aws_iam_role.sentinel_engine_role.arn
  handler          = "scanner.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  source_code_hash = data.archive_file.scanner_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.sentinel_tenants.name
    }
  }
}

# Grant Lambda permission to modify S3 objects and write mitigation alert flags
resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "sentinel-lambda-s3-access"
  role = aws_iam_role.sentinel_engine_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObjectTagging",
          "s3:PutObjectAcl"
        ]
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.tenant_storage.arn}/*"
      },
      {
        Action = [
          "dynamodb:PutItem"
        ]
        Effect   = "Allow"
        Resource = aws_dynamodb_table.sentinel_tenants.arn
      }
    ]
  })
}

# Trigger Lambda when a file is uploaded to S3
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.malware_scanner.arn
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.tenant_storage.arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.tenant_storage.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.malware_scanner.arn
    events              = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_lambda_permission.allow_s3]
}

# Output the new bucket name so we can test it easily
output "tenant_bucket_name" {
  value = aws_s3_bucket.tenant_storage.bucket
}
# ==========================================
# 6. ALERTING & NOTIFICATIONS (SNS)
# ==========================================
resource "aws_sns_topic" "security_alerts" {
  name = "sentinel-security-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "skmansoor.wk@gmail.com" # <--- REPLACE THIS WITH YOUR REAL EMAIL
}

output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}
