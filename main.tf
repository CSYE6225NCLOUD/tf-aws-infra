# VPC and Subnet Configuration
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

# Internet Gateway and Route Table
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


# Security Groups
# Application Security Group
# Load Balancer Security Group
resource "aws_security_group" "lb_security_group" {
  name        = "${var.project_name}-load-balancer-sg"
  description = "Security group for the load balancer"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Application Security Group
resource "aws_security_group" "app_sg" {
  name        = "application_security_group"
  description = "Security group for web application EC2 instances"
  vpc_id      = aws_vpc.my_vpc.id

  # SSH access (if required)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow traffic from the load balancer on the application port
  ingress {
    from_port       = var.application_port
    to_port         = var.application_port
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_security_group.id]
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

# IAM Roles and Instance Profile
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

resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "cloudwatch_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_agent_policy.arn
}

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
# RDS Instance
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
# Generate a UUID for the S3 bucket name
resource "random_uuid" "s3_bucket_name" {}

# S3 Bucket for User Images
resource "aws_s3_bucket" "user_images" {
  bucket        = random_uuid.s3_bucket_name.result
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

resource "random_string" "bucket_suffix" {
  length  = 6
  special = false
  upper   = false
}




# AWS Lambda Function
resource "aws_lambda_function" "email_verification" {
  function_name = "emailVerificationFunction"
  runtime       = "nodejs18.x"
  handler       = "index.handler"
  role          = aws_iam_role.lambda_execution_role.arn
  timeout       = 30
  memory_size   = 128
  filename      = "/Users/shubhamlakhotia/CloudComputing/serverless/Archive.zip"

  environment {
    variables = {
      SENDGRID_API_KEY    = var.sendgrid_api_key
      SENDGRID_FROM_EMAIL = var.sendgrid_from_email
      DOMAIN_NAME         = var.domain_name
      SNS_TOPIC_ARN       = aws_sns_topic.verification_topic.arn
    }
  }
}

# SNS Topic for Email Verification
resource "aws_sns_topic" "verification_topic" {
  name = "email-verification-topic"
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "verification_topic_policy" {
  arn = aws_sns_topic.verification_topic.arn

  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "EmailVerificationTopicPolicy",
    Statement = [
      {
        Sid    = "AllowLambdaToPublish",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action   = "sns:Publish",
        Resource = aws_sns_topic.verification_topic.arn,
        Condition = {
          ArnLike : {
            "AWS:SourceArn" : aws_lambda_function.email_verification.arn
          }
        }
      },
      {
        Sid    = "AllowSpecificIAMRoleToPublish",
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_role.ec2_role.arn
        },
        Action   = "sns:Publish",
        Resource = aws_sns_topic.verification_topic.arn
      }
    ]
  })
}

# Lambda Execution Role
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda_execution_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Policy for Lambda
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.project_name}-lambda-policy"
  description = "Policy for Lambda function to access SNS, RDS, and logs"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["sns:Publish"],
        Resource = aws_sns_topic.verification_topic.arn
      },
      {
        Effect = "Allow",
        Action = [
          "rds:DescribeDBInstances",
          "rds-db:connect"
        ],
        Resource = aws_db_instance.my_rds_instance.arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}


# Attach Policy to Role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# SNS Subscription for Lambda
resource "aws_sns_topic_subscription" "email_verification_lambda" {
  topic_arn = aws_sns_topic.verification_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.email_verification.arn
}

# Lambda Permission for SNS Invocation
resource "aws_lambda_permission" "allow_sns_to_invoke_lambda" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.email_verification.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.verification_topic.arn
}

# Launch Template
resource "aws_launch_template" "web_app_template" {
  name          = "launch-template"
  image_id      = var.custom_ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance_profile.name
  }

  network_interfaces {
    security_groups             = [aws_security_group.app_sg.id]
    associate_public_ip_address = true
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo "DB_HOST=${aws_db_instance.my_rds_instance.address}" >> /etc/webapp.env
    echo "DB_NAME=${var.db_name}" >> /etc/webapp.env
    echo "DB_USER=${var.username}" >> /etc/webapp.env
    echo "DB_PASSWORD=${var.db_password}" >> /etc/webapp.env
    echo "DB_DIALECT=mysql" >> /etc/webapp.env
    echo "S3_BUCKET_NAME=${aws_s3_bucket.user_images.bucket}" >> /etc/webapp.env
    echo "AWS_REGION=${var.aws_region}" >> /etc/webapp.env
    echo "SNS_TOPIC_ARN=${aws_sns_topic.verification_topic.arn}" >> /etc/webapp.env
    echo "DOMAIN_NAME=${var.domain_name}" >> /etc/webapp.env

    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

    sudo systemctl daemon-reload
    sudo systemctl enable webapp
    sleep 30
    sudo systemctl restart webapp
  EOF
  )

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 25
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-webapp-instance"
    }
  }
}


# Auto Scaling Group
resource "aws_autoscaling_group" "web_app_asg" {
  name                      = "ASG"
  desired_capacity          = 3
  min_size                  = 3
  max_size                  = 5
  vpc_zone_identifier       = tolist([for subnet in aws_subnet.public_subnet : subnet.id])
  target_group_arns         = [aws_lb_target_group.app_target_group.arn]
  health_check_grace_period = 300
  launch_template {
    id      = aws_launch_template.web_app_template.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "webapp-instance"
    propagate_at_launch = true
  }
}

# Scaling Policies
resource "aws_autoscaling_policy" "scale_up_policy" {
  name                   = "scale_up_policy"
  autoscaling_group_name = aws_autoscaling_group.web_app_asg.name
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 1
  cooldown               = 60
}

resource "aws_autoscaling_policy" "scale_down_policy" {
  name                   = "scale_down_policy"
  autoscaling_group_name = aws_autoscaling_group.web_app_asg.name
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = 60
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "scale_up_alarm" {
  alarm_name          = "scale_up_alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = var.threshold_scaleup
  alarm_actions       = [aws_autoscaling_policy.scale_up_policy.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_app_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "scale_down_alarm" {
  alarm_name          = "scale_down_alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = var.threshold_scaledown
  alarm_actions       = [aws_autoscaling_policy.scale_down_policy.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_app_asg.name
  }
}

# Application Load Balancer
resource "aws_lb" "application_lb" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_security_group.id]
  subnets            = aws_subnet.public_subnet[*].id
  tags = {
    Name = "${var.project_name}-alb"
  }
}

# ALB Listener
resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.application_lb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_target_group.arn
  }
}

# Target Group
resource "aws_lb_target_group" "app_target_group" {
  name     = "${var.project_name}-tg"
  port     = var.application_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.my_vpc.id

  health_check {
    path                = "/healthz"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.project_name}-tg"
  }
}

# Route 53 DNS Record
resource "aws_route53_record" "webapp" {
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_lb.application_lb.dns_name
    zone_id                = aws_lb.application_lb.zone_id
    evaluate_target_health = true
  }
}

# Output for S3 Bucket Name
output "s3_bucket_name" {
  description = "The name of the S3 bucket created for user images"
  value       = aws_s3_bucket.user_images.bucket
}
