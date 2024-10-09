
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