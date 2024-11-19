
variable "aws_region" {
  description = "The AWS region to deply the resources"
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS profile in use"
  default     = "default"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "private_subnets_cidrs" {
  description = "CIDR blocks for the private subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "public_subnets_cidrs" {
  description = "CIDR blocks for the public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "project_name" {
  description = "Project Name"
  default     = "tf-aws-infra"
}

variable "availability_zone" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "instance_type" {
  description = "The instance type"
  type        = string
  default     = "t2.micro"
}

variable "custom_ami_id" {
  description = "The custom AMI ID for your instance"
  type        = string
}

variable "application_port" {
  description = "The port on which the application runs."
  default     = 4100
}

variable "key_name" {
  type    = string
  default = "ubuntu"
}
variable "database_port" {
  description = "The port on which database runs."
  default     = 3306
}

variable "allocated_storage" {
  description = "Storage Allocation for database"
}

variable "db_engine" {
  description = "Database Engine"
}

variable "instance_class" {
  description = "Instance class of Relational Database"
}

variable "db_name" {
  description = "Name of the Database"
}

variable "username" {
  description = "Username of Database"
}

variable "db_password" {
  description = "Password of database"
}

variable "threshold_scaleup" {
  description = "threshold for scaleup"
}

variable "threshold_scaledown" {
  description = "threshold for scaledown"
}

variable "db_multi_authorization" {
  description = "Authorization for database"
  default     = false
}

variable "db_public_access" {
  description = "Public accessibility"
  default     = false
}

variable "route53_zone_id" {
  description = "The Route 53 hosted zone ID for DNS management"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the Route 53 hosted zone"
  type        = string
}

variable "environment" {
  description = "Environment name, e.g., dev or demo"
  type        = string
}

variable "sendgrid_api_key" {
  type        = string
  description = "API Key for SendGrid"
}

variable "sendgrid_from_email" {
  type        = string
  description = "Sender email address for SendGrid"
}