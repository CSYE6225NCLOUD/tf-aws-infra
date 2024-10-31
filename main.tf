resource "aws_vpc" "my_vpc" {
  cidr_block = var.vpc_cidr
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "public_subnet" {
  count             = length(var.public_subnets_cidrs)
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.public_subnets_cidrs[count.index]
  availability_zone = var.availability_zone[count.index]

  tags = {
    Name = "${var.project_name}-publicSubnet-${count.index + 1}"
    Type = "Public"
  }
}

resource "aws_subnet" "private_subnet" {
  count             = length(var.private_subnets_cidrs)
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.private_subnets_cidrs[count.index]
  availability_zone = var.availability_zone[count.index]

  tags = {
    Name = "${var.project_name}-privateSubnet-${count.index + 1}"
    Type = "Private"
  }
}


resource "aws_internet_gateway" "my_internet_gateway" {

  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "${var.project_name}-internetGateway"
  }
}


resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "${var.project_name}-publicRouteTable"
  }
}

resource "aws_route" "public_route" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.my_internet_gateway.id
}

resource "aws_route_table_association" "public_association" {
  count          = length(var.public_subnets_cidrs)
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "${var.project_name}-privateRouteTable"
  }
}

resource "aws_route_table_association" "private_association" {
  count          = length(var.private_subnets_cidrs)
  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_security_group" "app_sg" {
  name        = "application_security_group"
  description = "Security group for web application EC2 instances"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = var.application_port
    to_port     = var.application_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_security_group" "security_group_db" {
  name        = "security_group_database"
  description = "Security group for the database"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port       = var.database_port
    to_port         = var.database_port
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-security_group_db"
  }
}

# IAM Role for EC2 with S3 Permissions
resource "aws_iam_role" "ec2_role" {
  name = "${var.project_name}-ec2-s3-access-role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_policy" "cloudwatch_agent_policy" {
  name        = "CloudWatchAgentPolicy"
  description = "Policy to allow Cloudwatch Agent to publish custom metrics"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "cloudwatch:PutMetricData",
          "logs:PutLogEvents",
          "logs:CreateLogStream",
          "logs:CreateLogGroup",
        ],
        Resource = "*"
      }
    ]
  })
}



# IAM Policy allowing S3 access only to the specific bucket
resource "aws_iam_policy" "s3_policy" {
  name = "${var.project_name}-ec2-s3-policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        "Resource" : [
          "arn:aws:s3:::${aws_s3_bucket.user_images.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.user_images.bucket}/*"
        ]
      }
    ]
  })
}

# Attach the S3 policy to the IAM role
resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "cloudwatch_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_agent_policy.arn
}


# Instance profile to attach the IAM role to the EC2 instance
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${var.project_name}-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}


resource "aws_db_parameter_group" "parameter_group_db" {
  name        = "parameter-group-db"
  family      = "mysql8.0"
  description = "Parameter group"

  tags = {
    Name = "${var.project_name}-parameter-group-db"
  }
}

resource "aws_db_subnet_group" "subnet_group_db" {
  name       = "${var.project_name}-subnet_group_db"
  subnet_ids = aws_subnet.private_subnet[*].id

  tags = {
    Name = "${var.project_name}-subnet_group_db"
  }
}

resource "aws_db_instance" "my_rds_instance" {
  allocated_storage      = var.allocated_storage
  instance_class         = var.instance_class
  engine                 = var.db_engine
  db_name                = var.db_name
  username               = var.username
  password               = var.db_password
  parameter_group_name   = aws_db_parameter_group.parameter_group_db.name
  db_subnet_group_name   = aws_db_subnet_group.subnet_group_db.name
  multi_az               = var.db_multi_authorization
  publicly_accessible    = var.db_public_access
  vpc_security_group_ids = [aws_security_group.security_group_db.id]

  # Set this to true if you don't want a final snapshot when deleting the instance
  skip_final_snapshot = true

  # If skip_final_snapshot is set to false, you need to provide a snapshot identifier
  # final_snapshot_identifier = "my-final-snapshot-${var.name_of_db}"

  tags = {
    Name = "${var.project_name}-rds-instance"
  }
}



# S3 Bucket for User Images
resource "aws_s3_bucket" "user_images" {
  bucket        = "${var.project_name}-${random_string.bucket_suffix.result}"
  acl           = "private"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  tags = {
    Name = "${var.project_name}-user-images-bucket"
  }
}

# Random Suffix for Unique S3 Bucket Naming
resource "random_string" "bucket_suffix" {
  length  = 6
  special = false
  upper   = false
}



# Output for S3 Bucket Name
output "s3_bucket_name" {
  description = "The name of the S3 bucket created for user images"
  value       = aws_s3_bucket.user_images.bucket
}



# Create EC2 Instance
resource "aws_instance" "web_app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public_subnet[0].id
  associate_public_ip_address = true
  security_groups             = [aws_security_group.app_sg.id]
  key_name                    = var.key_name

  # Attach IAM instance profile
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
    #!/bin/bash
    echo "DB_HOST=${aws_db_instance.my_rds_instance.address}" >> /etc/webapp.env
    echo "DB_NAME=csye6225" >> /etc/webapp.env
    echo "DB_USER=csye6225" >> /etc/webapp.env
    echo "DB_PASSWORD=${var.db_password}" >> /etc/webapp.env
    echo "DB_DIALECT=mysql" >> /etc/webapp.env
    echo "S3_BUCKET_NAME=${aws_s3_bucket.user_images.bucket}" >> /etc/webapp.env
    echo "AWS_REGION=${var.aws_region}" >> /etc/webapp.env
  

    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

    # Start Webapp Service
    sudo systemctl daemon-reload
    sudo systemctl enable webapp
    sleep 30
    sudo systemctl restart webapp
  EOF

  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }


  tags = {
    Name = "WebAppInstance"
  }
}
resource "aws_route53_record" "webapp" {
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 60
  records = [aws_instance.web_app_instance.public_ip]

  depends_on = [aws_instance.web_app_instance]
}