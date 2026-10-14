# Suppressed Terraform Configuration for Integration Testing
# Demonstrates in-code rule suppression with audit justification

# strata:ignore AWS-CIS-S3-001 reason: Public assets bucket intentionally configured for CDN asset delivery
resource "aws_s3_bucket" "public_cdn" {
  bucket = "prod-public-marketing-assets-2026"
  acl    = "public-read"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
