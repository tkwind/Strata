# Vulnerable Terraform Configuration (Production Insecure Fixture)

resource "aws_s3_bucket" "customer_backup_data" {
  bucket = "prod-customer-backups-2026"
  acl    = "public-read"
}

resource "aws_security_group" "bastion_and_db_sg" {
  name        = "production-bastion-sg"
  description = "Allows SSH and Database ingress"

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL access"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "production_db" {
  identifier          = "corp-postgres-prod"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_iam_policy" "admin_wildcard_policy" {
  name   = "ci-deployment-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Accidental credential leak
# AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE
