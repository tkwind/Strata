# Hardened Terraform Configuration (CIS Benchmark Compliant Fixture)

resource "aws_s3_bucket" "secure_archive_bucket" {
  bucket = "prod-archive-vault-2026"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_security_group" "private_internal_sg" {
  name        = "private-vpc-sg"
  description = "Allows ingress only from trusted internal subnet"

  ingress {
    description = "Internal app communication"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "secure_database" {
  identifier          = "secure-db-instance"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = false
  storage_encrypted   = true
}
