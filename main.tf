
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



# Create EC2 Instance
resource "aws_instance" "web_app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public_subnet[0].id
  associate_public_ip_address = true
  security_groups             = [aws_security_group.app_sg.id]
  key_name                    = var.key_name

  user_data = <<-EOF
    #!/bin/bash
    echo "DB_HOST=${aws_db_instance.my_rds_instance.address}" >> /etc/webapp.env
    echo "DB_NAME=csye6225" >> /etc/webapp.env
    echo "DB_USER=csye6225" >> /etc/webapp.env
    echo "DB_PASSWORD=${var.db_password}" >> /etc/webapp.env
    echo "DB_DIALECT=mysql" >> /etc/webapp.env
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